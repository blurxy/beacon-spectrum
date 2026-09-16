#!/usr/bin/env python3
"""Synthetic beacons and benign background, for a labelled evaluation set.

Everything here is generated. No captured traffic, no malware, nothing that
needs a network. The point is ground truth: to plot detection rate against
jitter you need to know which flows are beacons, and real captures do not come
labelled.
"""
import numpy as np


def beacon(period, duration, jitter=0.0, rng=None, start=None):
    """Events every `period` seconds, each displaced by +/- jitter*period.

    Jitter is the percentage form operators actually configure in C2 frameworks
    (Cobalt Strike's `sleep 60 30` is 60s at 30%), so the curve is plotted
    against a number a defender recognises.
    """
    rng = rng or np.random.default_rng()
    n = int(duration / period)
    if n < 2:
        return np.array([])
    k = np.arange(n, dtype=np.float64)
    t = k * period
    if jitter > 0:
        t = t + rng.uniform(-jitter * period, jitter * period, n)
    t = t + (rng.uniform(0, period) if start is None else start)
    return np.sort(t[(t >= 0) & (t < duration)])


def poisson_flow(rate, duration, rng=None):
    """Aperiodic background: a homogeneous Poisson process."""
    rng = rng or np.random.default_rng()
    n = rng.poisson(rate * duration)
    return np.sort(rng.uniform(0, duration, n))


def human_flow(duration, rng=None, sessions=None):
    """Bursty, clumped traffic -- the shape ordinary human browsing makes.

    A Poisson null is too easy. Real benign traffic arrives in bursts with long
    gaps, which is exactly the regime where a naive periodicity score produces
    false positives, so the null set has to contain it.
    """
    rng = rng or np.random.default_rng()
    out = []
    sessions = sessions or max(1, int(rng.poisson(duration / 900.0)))
    for _ in range(sessions):
        s = rng.uniform(0, duration)
        for _ in range(int(rng.poisson(8)) + 1):
            out.append(s + abs(rng.normal(0, 25)))
    t = np.array(sorted(x for x in out if 0 <= x < duration))
    return t


def periodic_benign(duration, rng=None):
    """Legitimate periodic traffic: NTP, telemetry, health checks, backups.

    These ARE periodic, so they will score highly. Any honest false-positive
    number has to include them -- this is the category that makes the problem
    hard rather than the Poisson noise.
    """
    rng = rng or np.random.default_rng()
    period = float(rng.choice([64.0, 300.0, 600.0, 900.0, 3600.0]))
    return beacon(period, duration, jitter=float(rng.uniform(0.0, 0.05)), rng=rng)
