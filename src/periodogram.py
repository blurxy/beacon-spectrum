#!/usr/bin/env python3
"""Periodicity estimators for point processes (connection events).

WHY NOT A PLAIN FFT. An FFT assumes evenly spaced samples. Network connection
events are a POINT PROCESS: a list of irregular arrival times. There is no
sample rate.

WHY NOT LOMB-SCARGLE OVER THE INTERVALS EITHER. The obvious repair -- take the
inter-arrival gaps and run an irregular-sampling periodogram on them -- does not
work, and it is worth being precise about why, because it is the first thing
people reach for. A periodic beacon of period P produces intervals that are all
approximately P. That sequence is a constant plus noise; it does not oscillate.
Its periodogram is flat. The period is encoded in the VALUE of the intervals,
not in any frequency present among them.

WHAT ACTUALLY WORKS. Test phase coherence of the event times directly. For a
candidate frequency f, map every event onto the unit circle by its phase and sum:

    R(f) = (1/N) * | sum_k exp(2*pi*i*f*t_k) |

Events locked to period 1/f land at the same phase and the vectors add; events
scattered in time cancel. This is the Rayleigh test, standard in pulsar timing.
Under the null hypothesis of a homogeneous Poisson process,

    Z2 = 2*N*R(f)^2   ~   chi-squared with 2 degrees of freedom

which gives a calibrated p-value instead of an arbitrary score threshold.
"""
import numpy as np


def rayleigh_periodogram(times, freqs):
    """R(f) in [0,1] for each candidate frequency. 1 = perfect phase lock."""
    t = np.asarray(times, dtype=np.float64)
    n = t.size
    if n < 2:
        return np.zeros(len(freqs))
    # outer product (n_freqs, n_events); fine for the grids used here
    phase = 2.0 * np.pi * np.outer(np.asarray(freqs, dtype=np.float64), t)
    c = np.cos(phase).sum(axis=1)
    s = np.sin(phase).sum(axis=1)
    return np.hypot(c, s) / n


def z2_statistic(times, freqs):
    """Rayleigh power Z^2 = 2N R^2, chi2 with 2 dof under Poisson null."""
    n = len(times)
    return 2.0 * n * rayleigh_periodogram(times, freqs) ** 2


def freq_grid(times, pmin=1.0, pmax=None, oversample=8):
    """Candidate frequencies from the shortest period of interest to the span.

    Resolution is set by the observation window: two frequencies closer than
    1/T are not separable no matter how finely the grid is sampled, so the grid
    is built at 1/(oversample*T) and no finer -- sampling past that invents
    structure rather than resolving it.
    """
    t = np.asarray(times, dtype=np.float64)
    span = float(t.max() - t.min()) if t.size > 1 else 1.0
    if span <= 0:
        return np.array([1.0])
    if pmax is None:
        pmax = span / 3.0            # need >=3 cycles to claim a period
    pmax = max(pmax, pmin * 2)
    df = 1.0 / (oversample * span)
    return np.arange(1.0 / pmax, 1.0 / pmin + df, df)


def detect(times, pmin=1.0, pmax=None, oversample=8):
    """Best candidate period and its significance.

    Returns (period, z2, p_value, n_events). The p-value is corrected for the
    number of INDEPENDENT frequencies searched -- about span/pmin, not the grid
    length, since oversampling does not add independent trials. Skipping this
    correction is how a periodogram 'finds' a beacon in pure noise.
    """
    t = np.sort(np.asarray(times, dtype=np.float64))
    if t.size < 8:
        return None, 0.0, 1.0, int(t.size)
    f = freq_grid(t, pmin, pmax, oversample)
    z = z2_statistic(t, f)
    i = int(np.argmax(z))
    zmax = float(z[i])
    span = float(t[-1] - t[0])
    n_indep = max(1.0, span / pmin)
    p_single = float(np.exp(-zmax / 2.0))          # chi2_2 survival
    p = 1.0 - (1.0 - p_single) ** n_indep
    return float(1.0 / f[i]), zmax, p, int(t.size)


# --------------------------------------------------------------- baseline ---
def rita_style_score(times):
    """Time-domain control, in the shape RITA uses: dispersion + skew of gaps.

    Implemented here so the comparison in the README is against something real
    and measured on the same data, rather than against a number quoted from
    someone else's paper.
    """
    t = np.sort(np.asarray(times, dtype=np.float64))
    if t.size < 4:
        return 0.0
    d = np.diff(t)
    if d.size < 3 or np.median(d) <= 0:
        return 0.0
    mad = float(np.median(np.abs(d - np.median(d))))
    disp = 1.0 - mad / np.median(d)
    q1, q2, q3 = np.percentile(d, [25, 50, 75])
    skew = 0.0 if q3 - q1 <= 0 else abs((q3 + q1 - 2 * q2) / (q3 - q1))
    return float(max(0.0, min(1.0, (max(0.0, disp) + (1.0 - skew)) / 2.0)))
