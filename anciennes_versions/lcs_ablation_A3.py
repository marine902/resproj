"""
ABLATION A3 — Gaps bornés + Clustering + Filtres de qualité.
Améliorations actives : 1 + 2 + 3
Améliorations désactivées :
    - Paire médiane (alignement progressif k-LCS complet par cluster)
    - Alignement local (mode NW global uniquement)
"""

from __future__ import annotations
import argparse
import logging
import heapq
import edlib
import os
from time import monotonic
from typing import Dict, Tuple, List
from bisect import bisect_right
from multiprocessing import Pool
import signal
import sys
import statistics

TRUNCATE_BYTES_DEFAULT = 1000000

def read_truncated(sample_filepath: str, limit: int) -> bytes:
    with open(sample_filepath, 'rb') as file:
        return file.read(limit)

def worker_init():
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def collect_samples(samples_dirpath: str, limit: int, logger: logging.Logger) -> list[bytes]:
    samples_filepaths = [os.path.join(samples_dirpath, filename) for filename in sorted(os.listdir(samples_dirpath))]
    if not samples_filepaths:
        raise SystemExit(f"No files found in {samples_dirpath}")
    logger.info(f"Found {len(samples_filepaths)} files. Reading up to {limit} bytes each...")
    sequences: list[bytes] = []
    for filepath in samples_filepaths:
        data = read_truncated(filepath, limit)
        sequences.append(data)
    logger.info(f"Loaded {len(sequences)} byte sequences.")
    return sequences

def pair_lcs(a: bytes, b: bytes) -> bytes:
    res = edlib.align(a, b, mode="NW", task="path")
    cigar = res["cigar"]
    if cigar is None:
        return b""
    i = j = 0
    output = bytearray()
    run = 0
    for ch in cigar:
        if ch.isdigit():
            run = run * 10 + (ord(ch) - 48)
            continue
        if run == 0:
            run = 1
        if ch == "=":
            output.extend(a[i:i+run])
            i += run; j += run
        elif ch in ("X", "M"):
            i += run; j += run
        elif ch == "I":
            j += run
        elif ch == "D":
            i += run
        run = 0
    return bytes(output)

def _compute_edit_distance_task(args):
    i, j, a_bytes, b_bytes = args
    dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")["editDistance"]
    return (dist, i, j)

def build_distance_heap(items, active_ids, pool=None, logger=None):
    heap = []
    ids = list(active_ids)
    tasks = [(ids[ix], ids[jx], items[ids[ix]], items[ids[jx]]) for ix in range(len(ids)) for jx in range(ix+1, len(ids))]
    total = len(tasks)
    log_interval = max(1, total // 10)
    t0 = monotonic()
    if logger:
        logger.info(f"  Building heap: {total} pairs...")
    if pool and tasks:
        for done, (dist, i, j) in enumerate(pool.imap(_compute_edit_distance_task, tasks, chunksize=4), 1):
            heap.append((dist, i, j))
            if logger and done % log_interval == 0:
                logger.info(f"  [{done}/{total} | ETA ~{(monotonic()-t0)/done*(total-done):.0f}s]")
    else:
        for done, (i, j, a_b, b_b) in enumerate(tasks, 1):
            dist = edlib.align(a_b, b_b, mode="NW", task="distance")['editDistance']
            heap.append((dist, i, j))
            if logger and done % log_interval == 0:
                logger.info(f"  [{done}/{total} | ETA ~{(monotonic()-t0)/done*(total-done):.0f}s]")
    if logger:
        logger.info(f"  Heap built in {monotonic()-t0:.1f}s")
    heapq.heapify(heap)
    return heap


# ABLATION A3: clustering ACTIF
cluster_sample_bytes = 10000
cluster_threshold = 0.8

def cluster_samples(sequences: list[bytes], logger: logging.Logger):
    n = len(sequences)
    prefix = [s[:cluster_sample_bytes] for s in sequences]
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        a, b = find(x), find(y)
        if a != b:
            parent[a] = b

    all_distances = {}
    for i in range(n):
        for j in range(i+1, n):
            d = edlib.align(prefix[i], prefix[j], mode="NW", task="distance")["editDistance"]
            all_distances[(i, j)] = d

    max_distance = max(all_distances.values()) if all_distances else 0
    threshold_distance = cluster_threshold * max_distance
    for (i, j), d in all_distances.items():
        if d <= threshold_distance:
            union(i, j)

    clusters = {}
    for i in range(n):
        s = find(i)
        if s not in clusters:
            clusters[s] = []
        clusters[s].append(i)
    result = list(clusters.values())
    logger.info(f"Clustering: {len(result)} clusters formed")
    return result


def k_lcs(sequences: list[bytes], *, logger: logging.Logger, workers: int) -> bytes:
    if not sequences:
        return b""
    items = {id: seq for id, seq in enumerate(sequences)}
    active = set(items.keys())
    total_steps = len(sequences) - 1
    pool = None
    if workers:
        pool = Pool(processes=workers, initializer=worker_init)
    step = 1
    try:
        while len(active) > 1:
            heap = build_distance_heap(items, active, pool, logger=logger)
            dist, i, j = heapq.heappop(heap)
            lcs_ij = pair_lcs(items[i], items[j])
            keep_id, drop_id = (i, j) if i < j else (j, i)
            items[keep_id] = lcs_ij
            active.remove(drop_id)
            del items[drop_id]
            if lcs_ij:
                allowed = set(lcs_ij)
                for k in active:
                    if k != keep_id:
                        items[k] = bytes(b for b in items[k] if b in allowed)
            step += 1
    except KeyboardInterrupt:
        if pool is not None:
            pool.terminate(); pool.join(); pool = None
        raise
    finally:
        if pool is not None:
            pool.close(); pool.join()
    return items[next(iter(active))]


# ABLATION A3: filtres de qualité ACTIFS
min_block_bytes = 8
min_unique_ratio = 0.25
min_sequence_length = 20
max_sequence_ratio = 0.85
max_null_ratio = 0.4

def clean_block(tokens: list[str]) -> list[str] | None:
    hex_tokens = [t for t in tokens if not t.startswith("[")]
    if len(hex_tokens) < min_block_bytes:
        return None
    if len(set(hex_tokens)) / len(hex_tokens) < min_unique_ratio:
        return None
    byte_vals = [int(t, 16) for t in hex_tokens]
    seq_count = sum(1 for i in range(len(byte_vals)-1) if byte_vals[i+1]-byte_vals[i] == 1)
    if len(byte_vals) > min_sequence_length and seq_count/(len(byte_vals)-1) > max_sequence_ratio:
        return None
    if sum(1 for t in hex_tokens if t == "00") / len(hex_tokens) > max_null_ratio:
        return None
    if len(hex_tokens) >= 2 and hex_tokens[0] == "4d" and hex_tokens[1] == "5a":
        for i, t in enumerate(tokens):
            if t == "5a":
                tokens = tokens[i+1:]
                break
    return tokens


# ABLATION A3: filter_yara_strings ACTIF
def filter_yara_strings(strings: list[str], max_null_ratio: float = 0.3) -> list[str]:
    filtered = []
    for s in strings:
        tockens = s.strip("{} ").split()
        bytes_only = [t for t in tockens if not t.startswith("[")]
        if len(bytes_only) >= 2 and bytes_only[0] == '4d' and bytes_only[1] == '5a':
            continue
        if not bytes_only:
            continue
        if sum(1 for t in bytes_only if t == "00") / len(bytes_only) > 0.5:
            continue
        if len(set(bytes_only)) / len(bytes_only) < 0.10:
            continue
        byte_vals = [int(t, 16) for t in bytes_only]
        differences = [byte_vals[i+1] - byte_vals[i] for i in range(len(byte_vals)-1)]
        if len(differences) > 20 and sum(1 for d in differences if d == 1) / len(differences) > 0.85:
            continue
        filtered.append(s)
    return filtered


min_block_size = 16
max_gap_size = 50
max_block_bytes = 500
max_strings_per_cluster = 20


def yara_format_lcs(lcs: bytes, sequences: list[bytes], *, bytes_per_line: int = 24) -> list[str]:
    """Formats LCS into YARA hex strings with bounded [min-max] gaps."""
    def sequence_lcs_bytes_positions(sequence, lcs):
        buckets = [[] for _ in range(256)]
        for idx, b in enumerate(sequence):
            buckets[b].append(idx)
        pos = []
        curr_index = -1
        for b in lcs:
            b_positions = buckets[b]
            k = bisect_right(b_positions, curr_index)
            if k == len(b_positions):
                return None
            curr_index = b_positions[k]
            pos.append(curr_index)
        return pos

    if not lcs:
        return []
    positions = [p for seq in sequences if (p := sequence_lcs_bytes_positions(seq, lcs)) is not None]
    yara_strings = []
    tokens = [f"{lcs[0]:02x}"]
    for i in range(len(lcs) - 1):
        contiguous_in_all = all(p[i+1] == p[i] + 1 for p in positions)
        if not contiguous_in_all:
            gaps = [p[i+1] - p[i] for p in positions]
            gap_min, gap_max = min(gaps), max(gaps)
            if gap_max > 50:
                clean = clean_block(tokens)
                if clean is not None:
                    yara_strings.append(clean)
                tokens = [f"{lcs[i+1]:02x}"]
            else:
                tokens.append("["+str(gap_min)+"-"+str(gap_max)+"]")
                tokens.append(f"{lcs[i+1]:02x}")
        else:
            tokens.append(f"{lcs[i+1]:02x}")
    clean = clean_block(tokens)
    if clean is not None:
        yara_strings.append(clean)
    return ["{ " + " ".join(t) + " }" for t in yara_strings]


def build_yara_rule_text(family, yara_strings, time_to_build):
    strings_block = "".join(f"        $s{i} = {s}\n" for i, s in enumerate(yara_strings))
    rt = f"{round(time_to_build, 2)} sec" if time_to_build < 60 else f"{round(time_to_build/60, 2)} min"
    return f"rule {family}\n{{\n    meta:\n        family = \"{family}\"\n        time_to_build = \"{rt}\"\n    strings:\n{strings_block}\n    condition:\n        any of them\n}}"


def main():
    ap = argparse.ArgumentParser(description="ABLATION A3 — Bounded gaps + Clustering + Filters")
    ap.add_argument("family_dirpath", type=str)
    ap.add_argument("--truncate-bytes", type=int, default=TRUNCATE_BYTES_DEFAULT)
    ap.add_argument("-v", "--verbose", action="count", default=0)
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--batch-size", type=int, default=None)
    args = ap.parse_args()

    level = logging.WARNING if args.verbose == 0 else (logging.INFO if args.verbose == 1 else logging.DEBUG)
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)-5s | %(message)s")
    logger = logging.getLogger("LCS_A3")

    family_dirpath = args.family_dirpath
    if not os.path.isdir(family_dirpath):
        raise SystemExit(f"Not a directory: {family_dirpath}")
    family = os.path.basename(os.path.normpath(family_dirpath))

    try:
        start_time = monotonic()
        sequences = collect_samples(family_dirpath, args.truncate_bytes, logger)
        if args.batch_size:
            sequences = sequences[:args.batch_size]

        # ABLATION A3: clustering ACTIF
        clusters = cluster_samples(sequences, logger)

        all_yara_strings = []
        for cluster in clusters:
            cluster_sequences = [sequences[i] for i in cluster]
            # ABLATION A3: k-LCS progressif NW global (pas de paire médiane)
            if len(cluster_sequences) < 2:
                continue
            lcs = k_lcs(cluster_sequences, logger=logger, workers=args.workers)
            yara_strings = yara_format_lcs(lcs, cluster_sequences)
            # ABLATION A3: filtres ACTIFS
            yara_strings = filter_yara_strings(yara_strings)
            all_yara_strings.extend(yara_strings)

        time_to_build = monotonic() - start_time

        if not all_yara_strings:
            print(f"No signature for {family}")
        else:
            rule_text = build_yara_rule_text(family, all_yara_strings, time_to_build)
            out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures_ablation", "A3", family)
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, f"{family}.yar")
            with open(out_path, 'w') as f:
                f.write(rule_text)
            print(f"Wrote signature to {out_path}")

    except KeyboardInterrupt:
        logger.error("Interrupted.")
        sys.exit(1)

if __name__ == "__main__":
    main()
