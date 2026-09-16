#!/usr/bin/env python3
"""End-to-end: write a pcap with a KNOWN beacon, read it back, recover the period.

The detector is never told the period. If ingestion drops packets, mis-parses
timestamps, or groups flows wrongly, the recovered period will not match the
planted one -- which makes this a test of the whole path rather than of the
periodogram in isolation.
"""
import os, sys, struct, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
from ingest import from_pcap, summarise
from periodogram import detect
from simulate import beacon, poisson_flow


def ip4(a): return bytes(int(x) for x in a.split("."))


def syn(src, dst, dport, sport=40000):
    ip = (b"\x45\x00" + struct.pack("!H", 40) + b"\x00\x01\x00\x00\x40\x06\x00\x00"
          + ip4(src) + ip4(dst))
    tcp = (struct.pack("!HH", sport, dport) + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x00"
           + b"\x50\x02" + b"\x20\x00\x00\x00\x00\x00")
    eth = b"\x00" * 12 + b"\x08\x00"
    return eth + ip + tcp


def write_pcap(path, events):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for t, pkt in sorted(events):
            fh.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(pkt), len(pkt)))
            fh.write(pkt)


def main():
    rng = np.random.default_rng(11)
    PERIOD, DUR, BASE = 45.0, 7200.0, 1.7e9
    events = []
    for t in beacon(PERIOD, DUR, jitter=0.08, rng=rng):
        events.append((BASE + t, syn("10.0.0.5", "203.0.113.9", 443)))
    planted = len(events)
    # background: two noisy flows and one benign periodic one, so the beacon has
    # to be picked OUT of something rather than found in an empty capture
    for t in poisson_flow(0.02, DUR, rng):
        events.append((BASE + t, syn("10.0.0.5", "198.51.100.4", 80)))
    for t in poisson_flow(0.01, DUR, rng):
        events.append((BASE + t, syn("10.0.0.7", "198.51.100.9", 443)))
    for t in beacon(64.0, DUR, jitter=0.01, rng=rng):
        events.append((BASE + t, syn("10.0.0.5", "203.0.113.200", 123)))

    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "capture.pcap")
    write_pcap(path, events)
    size = os.path.getsize(path)

    flows = from_pcap(path)
    print("wrote %d packets (%d of them the planted beacon), %.1f KB" % (len(events), planted, size / 1024))
    print("parsed %d flows back out\n" % len(flows))

    key = ("10.0.0.5", "203.0.113.9", 443)
    assert key in flows, "the beacon flow did not survive the round trip"
    got = len(flows[key])
    assert got == planted, "packet loss in ingest: planted %d, read %d" % (planted, got)
    print("  round trip: %d/%d beacon packets recovered" % (got, planted))

    print("\n%-34s %7s %10s %10s" % ("flow", "events", "period", "p-value"))
    hits = 0
    for k, times in summarise(flows):
        p, z, pv, n = detect(times, pmin=20.0, oversample=4)
        flag = ""
        if k == key:
            err = abs(p - PERIOD) / PERIOD
            assert err < 0.02, "recovered %.2fs, planted %.2fs" % (p, PERIOD)
            flag = "  <- planted beacon, %.1fs vs %.1fs planted" % (p, PERIOD)
            hits += 1
        print("%-34s %7d %9.1fs %10.2e%s" % ("%s -> %s:%d" % k, n, p or 0, pv, flag))
    assert hits == 1
    print("\nself-test: ingest round-trips, and the planted period is recovered end to end")


if __name__ == "__main__":
    main()
