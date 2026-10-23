"""Unit tests for the v1.3.0 reference STC (review R3-005): one test per Table 2
row of the paper plus one per defect fixed in v1.3.0."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stc.stc import (AnomalyRule, EventType, PaymentEvent,  # noqa: E402
                     SemanticTransactionCorrelator)

_n = [0]


def ev(et, ts, bin_="411111", stan=None, code=None, sid=None, tavv=None, amount=49.0,
       term="T1", ip="10.0.0.1"):
    _n[0] += 1
    return PaymentEvent(event_id=f"e{_n[0]}", event_type=et, bin_prefix=bin_, terminal_id=term,
                        source_ip=ip, timestamp=ts, stan=stan, amount=amount, response_code=code,
                        threeds_session_id=sid, tavv=tavv)


def stc(flow="dual_0220", **kw):
    return SemanticTransactionCorrelator(window_s=3600.0, flow=flow, **kw)


def only_seq(s, bin_="411111"):
    ids = s.bin_sequences[bin_]
    assert len(ids) == 1, ids
    return s.sequences[ids[0]]


# ---- defects fixed in v1.3.0 --------------------------------------------------

def test_legitimate_reversal_is_coherent():
    """R3-005(a): 0100, approved 0110, 0400 must not raise R-05."""
    s = stc()
    s.ingest_event(ev(EventType.ISO_0100, 0, stan="1"))
    s.ingest_event(ev(EventType.ISO_0110, 0.5, stan="1", code="00"))
    s.ingest_event(ev(EventType.ISO_0400, 10, stan="1"))
    r = s.compute_tcs("411111", 3500)
    assert r.tcs_str == 1.0 and r.total_sequences == 1
    assert AnomalyRule.R05 not in only_seq(s).anomaly_flags


def test_unsolicited_reversal_flags_r05():
    s = stc()
    s.ingest_event(ev(EventType.ISO_0400, 10, stan="999"))
    assert AnomalyRule.R05 in only_seq(s).anomaly_flags


def test_missing_response_flags_r01_not_r02():
    """R3-005(e): an unanswered 0100 is R-01; R-02 needs an approval."""
    s = stc()
    s.ingest_event(ev(EventType.ISO_0100, 0, stan="1"))
    s.compute_tcs("411111", 3500)
    flags = only_seq(s).anomaly_flags
    assert AnomalyRule.R01 in flags and AnomalyRule.R02 not in flags


def test_declined_terminal_is_coherent():
    """R3-005(f): a declined authorization is a terminal, coherent sequence."""
    s = stc()
    s.ingest_event(ev(EventType.ISO_0100, 0, stan="1"))
    s.ingest_event(ev(EventType.ISO_0110, 0.4, stan="1", code="54"))
    r = s.compute_tcs("411111", 3500)
    assert r.tcs_str == 1.0 and r.total_sequences == 1


def test_late_response_flags_r01():
    s = stc()
    s.ingest_event(ev(EventType.ISO_0100, 0, stan="1"))
    s.ingest_event(ev(EventType.ISO_0110, 7.0, stan="1", code="00"))
    assert AnomalyRule.R01 in only_seq(s).anomaly_flags


def test_areq_and_0100_join_one_sequence():
    """R3-005(g): the 3DS transaction id joins the AReq to its 0100."""
    s = stc()
    s.ingest_event(ev(EventType.THREEDS_AREQ, 0, sid="3ds-1"))
    s.ingest_event(ev(EventType.THREEDS_ARES, 1, sid="3ds-1"))
    s.ingest_event(ev(EventType.ISO_0100, 5, stan="1", sid="3ds-1"))
    s.ingest_event(ev(EventType.ISO_0110, 5.5, stan="1", code="00"))
    s.ingest_event(ev(EventType.ISO_0220, 60, stan="1"))
    assert len(s.bin_sequences["411111"]) == 1
    r = s.compute_tcs("411111", 3500)
    assert r.tcs_str == 1.0


def test_in_flight_sequences_are_excluded():
    """R3-004/R3-006: an approved authorization inside its capture window is in
    flight and does not count as coherent."""
    s = stc()
    s.ingest_event(ev(EventType.ISO_0100, 0, stan="1"))
    s.ingest_event(ev(EventType.ISO_0110, 0.4, stan="1", code="00"))
    r = s.compute_tcs("411111", 100)
    assert r.total_sequences == 0 and r.in_flight_sequences == 1


# ---- Table 2 rows -------------------------------------------------------------

def test_table2_vector_a_abandoned_3ds_session():
    """Row A: paced AReqs with no CReq and no 0100 are flagged R-06 and TCS falls."""
    s = stc()
    for i in range(30):
        s.ingest_event(ev(EventType.THREEDS_AREQ, i * 30.0, sid=f"a{i}", ip=f"1.1.1.{i}"))
        s.ingest_event(ev(EventType.THREEDS_ARES, i * 30.0 + 1, sid=f"a{i}", ip=f"1.1.1.{i}"))
    r = s.compute_tcs("411111", 3000)
    assert r.anomaly_distribution.get("R06", 0) == 30
    assert r.tcs_str == 0.0


def test_table2_vector_b_orphaned_approval():
    """Row B: approved 0100 without capture or reversal is flagged R-02."""
    s = stc(flow="dual_0220", completion_window_s=120.0)
    for i in range(10):
        s.ingest_event(ev(EventType.ISO_0100, i, stan=str(i)))
        s.ingest_event(ev(EventType.ISO_0110, i + 0.5, stan=str(i), code="00"))
    r = s.compute_tcs("411111", 500)
    assert r.anomaly_distribution.get("R02", 0) == 10 and r.tcs_str == 0.0


def test_table2_vector_c_fdce_is_structurally_coherent_but_distributionally_not():
    """Row C: declined sequences are structurally coherent; the distributional
    term collapses through the watched-code share and the completion rate."""
    s = stc(flow="dual_0220", completion_window_s=60.0, rho_star=0.5)
    # default R-11 statistic: decline share minus baseline (prior 0.12)
    for i in range(100):
        s.ingest_event(ev(EventType.ISO_0100, i, stan=str(i)))
        s.ingest_event(ev(EventType.ISO_0110, i + 0.3, stan=str(i), code="54"))
    r = s.compute_tcs("411111", 400)
    assert r.tcs_str == 1.0
    assert abs(r.watched_share - 0.88) < 1e-9 and r.completion_rate == 0.0
    assert r.tcs_dst == 0.0 and r.tcs == 0.0


def test_table2_vector_d_orphaned_token():
    """Row D: a provisioned cryptogram never used by an authorization is R-13."""
    s = stc()
    for i in range(5):
        s.ingest_event(ev(EventType.TOKEN_PROVISION, i * 10.0, tavv=f"tv{i}"))
    r = s.compute_tcs("411111", 1000)
    assert r.anomaly_distribution.get("R13", 0) == 5 and r.tcs_str == 0.0


def test_table2_vector_d_used_token_is_coherent():
    s = stc()
    s.ingest_event(ev(EventType.TOKEN_PROVISION, 0, tavv="tv1"))
    s.ingest_event(ev(EventType.ISO_0100, 5, stan="1", tavv="tv1"))
    s.ingest_event(ev(EventType.ISO_0110, 5.5, stan="1", code="00"))
    s.ingest_event(ev(EventType.ISO_0220, 100, stan="1"))
    assert len(s.bin_sequences["411111"]) == 1
    r = s.compute_tcs("411111", 3500)
    assert r.tcs_str == 1.0


def test_table2_vector_e_no_transaction_state():
    """Row E: load that creates no transaction state leaves TCS at its prior."""
    s = stc()
    r = s.compute_tcs("411111", 100)
    assert r.total_sequences == 0 and r.tcs == 1.0 and r.prior_used


# ---- flows ---------------------------------------------------------------------

def test_single_message_flow_approved_0210_is_capture():
    s = stc(flow="single")
    s.ingest_event(ev(EventType.ISO_0200, 0, stan="1"))
    s.ingest_event(ev(EventType.ISO_0210, 0.5, stan="1", code="00"))
    r = s.compute_tcs("411111", 100)
    assert r.tcs_str == 1.0 and r.completion_rate is None  # below the 20-cohort floor


def test_token_replay_flags_r08():
    s = stc()
    s.ingest_event(ev(EventType.ISO_0100, 0, stan="1", tavv="tvX"))
    s.ingest_event(ev(EventType.ISO_0100, 5, stan="2", tavv="tvX"))
    flags = [f for sid in s.bin_sequences["411111"] for f in s.sequences[sid].anomaly_flags]
    assert AnomalyRule.R08 in flags


def test_watched_share_mode():
    s = stc(flow="dual_0220", completion_window_s=60.0, rho_star=0.5, r11_mode="watched_share")
    for i in range(100):
        s.ingest_event(ev(EventType.ISO_0100, i, stan=str(i)))
        s.ingest_event(ev(EventType.ISO_0110, i + 0.3, stan=str(i), code="51"))
    r = s.compute_tcs("411111", 400)
    assert r.watched_share == 0.0 and r.completion_rate == 0.0 and r.tcs_dst == 0.0


def test_r03_scales_with_family_rate():
    """v1.3.0: a family carrying 20 organic TPS is not an enumeration burst; a jump
    to 200 per second in the same family is."""
    s = stc()
    n = 0
    for i in range(20 * 300):                     # 300 s at 20 per second
        s.ingest_event(ev(EventType.ISO_0100, i / 20.0, stan=f"o{i}", ip=f"ip{i}"))
        n += 1
    flags = sum(1 for sid in s.bin_sequences["411111"] if AnomalyRule.R03 in s.sequences[sid].anomaly_flags)
    assert flags == 0
    for j in range(200):                          # 200 in one second
        s.ingest_event(ev(EventType.ISO_0100, 300.0 + j / 200.0, stan=f"b{j}", ip=f"b{j}"))
    flags = sum(1 for sid in s.bin_sequences["411111"] if AnomalyRule.R03 in s.sequences[sid].anomaly_flags)
    assert flags > 0
