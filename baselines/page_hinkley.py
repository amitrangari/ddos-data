"""
Page-Hinkley test (v1.3.0, review R3-023): a standard drift detector applied to
the same daily JS-divergence series BIM's CUSUM sees (JS of the day's
distribution against the week-aligned reference).

    m_t = sum_{i<=t} (x_i - xbar_i - delta),  M_t = min_{i<=t} m_i,
    alarm when m_t - M_t > lambda

xbar_i is the running mean of x_1..x_i. delta and lambda are calibrated with
the same Monte Carlo procedure and false-alarm target as BIM.
"""


class PageHinkley:
    def __init__(self, delta: float, lam: float):
        self.delta, self.lam = delta, lam
        self.n = 0
        self.mean = 0.0
        self.m = 0.0
        self.M = 0.0
        self.alarm = False

    def update(self, x: float) -> bool:
        self.n += 1
        self.mean += (x - self.mean) / self.n
        self.m += x - self.mean - self.delta
        self.M = min(self.M, self.m)
        if not self.alarm and self.m - self.M > self.lam:
            self.alarm = True
            return True
        return False
