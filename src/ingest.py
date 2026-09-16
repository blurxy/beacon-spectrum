#!/usr/bin/env python3
"""Turn real captures into per-flow event times.

Two inputs, because those are what people actually have: a Zeek conn.log, or a
pcap. Both reduce to the same thing -- for each (src, dst, dst_port), the list
of times at which a connection STARTED. Only starts matter: a beacon is periodic
in when it reaches out, and counting every packet would measure the transfer
rather than the schedule.

pcap is parsed here rather than with scapy or dpkt. The format is a fixed global
header and a fixed per-packet header, and only the SYN of each TCP flow is
needed, so the parser is short and this keeps the project dependency-free --
which matters for a tool a defender is asked to run on a sensor.
"""
import struct, gzip, io, os
from collections import defaultdict

# Endianness is decided by what a LITTLE-ENDIAN read of the magic returns. If it
# comes back as the canonical constant, the file was written in the same order we
# just read in -- so it is little-endian. Getting this backwards parses every
# length field as a huge number and the reader walks off the end of the file
# immediately, returning zero flows and no error.
PCAP_MAGIC = {0xa1b2c3d4: ("<", 1e6), 0xd4c3b2a1: (">", 1e6),
              0xa1b23c4d: ("<", 1e9), 0x4d3cb2a1: (">", 1e9)}


def _open(path):
    return gzip.open(path, "rb") if path.endswith(".gz") else open(path, "rb")


def from_pcap(path, starts_only=True):
    """Flow start times from a pcap. Returns {(src,dst,dport): [t, ...]}."""
    flows = defaultdict(list)
    with _open(path) as fh:
        hdr = fh.read(24)
        if len(hdr) < 24:
            return {}
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic not in PCAP_MAGIC:
            raise ValueError("not a pcap: magic 0x%08x in %s" % (magic, path))
        end, divisor = PCAP_MAGIC[magic]
        linktype = struct.unpack(end + "I", hdr[20:24])[0]
        while True:
            ph = fh.read(16)
            if len(ph) < 16:
                break
            ts, tus, caplen, _orig = struct.unpack(end + "IIII", ph)
            pkt = fh.read(caplen)
            if len(pkt) < caplen:
                break
            t = ts + tus / divisor
            rec = _parse(pkt, linktype, starts_only)
            if rec:
                flows[rec].append(t)
    return {k: sorted(v) for k, v in flows.items()}


def _parse(pkt, linktype, starts_only):
    off = 14 if linktype == 1 else (4 if linktype == 101 else 0)   # EN10MB / RAW
    if linktype == 1:
        if len(pkt) < 14:
            return None
        if struct.unpack("!H", pkt[12:14])[0] != 0x0800:           # IPv4 only for now
            return None
    if len(pkt) < off + 20:
        return None
    ip = pkt[off:]
    if (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    if proto == 6:                                                  # TCP
        if len(ip) < ihl + 14:
            return None
        dport = struct.unpack("!H", ip[ihl + 2:ihl + 4])[0]
        flags = ip[ihl + 13]
        if starts_only and not (flags & 0x02 and not flags & 0x10):  # SYN, not SYN-ACK
            return None
        return (src, dst, dport)
    if proto == 17:                                                 # UDP
        if len(ip) < ihl + 8:
            return None
        dport = struct.unpack("!H", ip[ihl + 2:ihl + 4])[0]
        return (src, dst, dport)
    return None


def from_zeek(path):
    """Flow start times from a Zeek conn.log (TSV, with or without #fields)."""
    flows = defaultdict(list)
    cols = None
    with (gzip.open(path, "rt") if path.endswith(".gz") else open(path, "r")) as fh:
        for line in fh:
            if line.startswith("#"):
                if line.startswith("#fields"):
                    cols = line.rstrip("\n").split("\t")[1:]
                continue
            parts = line.rstrip("\n").split("\t")
            if cols is None:
                # headerless conn.log: the documented default column order
                cols = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"]
            d = dict(zip(cols, parts))
            try:
                t = float(d["ts"])
                key = (d["id.orig_h"], d["id.resp_h"], int(d["id.resp_p"]))
            except (KeyError, ValueError):
                continue
            flows[key].append(t)
    return {k: sorted(v) for k, v in flows.items()}


def load(path):
    if path.endswith((".log", ".log.gz", ".tsv")):
        return from_zeek(path)
    return from_pcap(path)


def summarise(flows, min_events=8):
    """Flows worth testing, largest first. Below min_events there is nothing to say."""
    rows = [(k, v) for k, v in flows.items() if len(v) >= min_events]
    rows.sort(key=lambda kv: -len(kv[1]))
    return rows
