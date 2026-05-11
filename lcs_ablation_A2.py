"""
ABLATION A2 — Gaps bornés + Clustering Union-Find.
Améliorations actives : 1 (gaps [min-max]) + 2 (clustering Union-Find)
Améliorations désactivées :
    - Filtres de qualité (filter_yara_strings désactivé)
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
    for idx, filepath in enumerate(samples_filepaths, 1):
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
            i += run
            j += run
        elif ch in ("X", "M"):
            i += run
            j += run
        elif ch == "I":
            j += run
        elif ch == "D":
            i += run
        run = 0
    return bytes(output)

def _compute_edit_distance_task(args: Tuple[int, int, bytes, bytes]) -> Tuple[int, int, int]:
    i, j, a_bytes, b_bytes = args
    dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")["editDistance"]
    return (dist, i, j)

def build_distance_heap(items: Dict[int, bytes], active_ids: set[int], pool=None, logger=None):
    heap = []
    ids = list(active_ids)
    n = len(ids)
    tasks = []
    for ix in range(n):
        i = ids[ix]
        for jx in range(ix + 1, n):
            j = ids[jx]
            tasks.append((i, j, items[i], items[j]))
    total = len(tasks)
    log_interval = max(1, total // 10)
    t_heap_start = monotonic()
    if logger:
        logger.info(f"  Building distance heap: {total} pairs ({n} sequences)...")
    if pool and tasks:
        for done, (dist, i, j) in enumerate(pool.imap(_compute_edit_distance_task, tasks, chunksize=4), 1):
            heap.append((dist, i, j))
            if logger and done % log_interval == 0:
                elapsed = monotonic() - t_heap_start
                eta = elapsed / done * (total - done)
                logger.info(f"  [{done}/{total} | {done*100//total}% | ETA ~{eta:.0f}s]")
    else:
        for done, (i, j, a_bytes, b_bytes) in enumerate(tasks, 1):
            dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")['editDistance']
            heap.append((dist, i, j))
            if logger and done % log_interval == 0:
                elapsed = monotonic() - t_heap_start
                eta = elapsed / done * (total - done)
                logger.info(f"  [{done}/{total} | {done*100//total}% | ETA ~{eta:.0f}s]")
    if logger:
        logger.info(f"  Heap built in {monotonic() - t_heap_start:.1f}s")
    heapq.heapify(heap)
    return heap


# ABLATION A2: clustering Union-Find ACTIF
cluster_sample_bytes = 10000
cluster_threshold = 0.8

def cluster_samples(sequences: list[bytes], logger: logging.Logger):
    """Regroup sequences in clusters via Union-Find (Amélioration 2)."""
    n = len(sequences)
    prefix = [s[:cluster_sample_bytes] for s in sequences]
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        a = find(x)
        b = find(y)
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
    items: Dict[int, bytes] = {id: seq for id, seq in enumerate(sequences)}
    active = set(items.keys())
    total_steps = len(sequences) - 1
    pool = None
    if workers:
        pool = Pool(processes=workers, initializer=worker_init)
    step = 1
    try:
        while len(active) > 1:
            logger.info(f"[step {step}/{total_steps}] {len(active)} sequences remaining...")
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
            pool.terminate()
            pool.join()
            pool = None
        raise
    finally:
        if pool is not None:
            pool.close()
            pool.join()
    last_id = next(iter(active))
    return items[last_id]


min_block_bytes = 8
min_unique_ratio = 0.25
min_sequence_length = 20
max_sequence_ratio = 0.85
max_null_ratio = 0.4

def clean_block(tokens: list[str]) -> list[str] | None:
    hex_tokens = [t for t in tokens if not t.startswith("[")]
    if len(hex_tokens) < min_block_bytes:
        return None
    unique_ratio = len(set(hex_tokens)) / len(hex_tokens)
    if unique_ratio < min_unique_ratio:
        return None
    byte_vals = [int(t, 16) for t in hex_tokens]
    seq_count = sum(1 for i in range(len(byte_vals)-1) if byte_vals[i+1]-byte_vals[i] == 1)
    if len(byte_vals) > min_sequence_length and seq_count/(len(byte_vals)-1) > max_sequence_ratio:
        return None
    null_ratio = sum(1 for t in hex_tokens if t == "00") / len(hex_tokens)
    if null_ratio > max_null_ratio:
        return None
    if len(hex_tokens) >= 2 and hex_tokens[0] == "4d" and hex_tokens[1] == "5a":
        for i, t in enumerate(tokens):
            if t == "5a":
                tokens = tokens[i+1:]
                break
    return tokens


# ABLATION A2: filter_yara_strings désactivé
def filter_yara_strings(strings: list[str], max_null_ratio: float = 0.3) -> list[str]:
    # ABLATION A2: filtrage de second passage désactivé
    return strings


min_block_size = 16
max_gap_size = 50
max_block_bytes = 500
max_strings_per_cluster = 20


def yara_format_lcs(lcs: bytes, sequences: list[bytes], *, bytes_per_line: int = 24) -> list[str]:
    """Formats LCS into YARA hex strings with bounded [min-max] gaps (Amélioration 1)."""
    def sequence_lcs_bytes_positions(sequence: bytes, lcs: bytes) -> list[int] | None:
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
    positions = []
    for sequence in sequences:
        p = sequence_lcs_bytes_positions(sequence, lcs)
        if p is not None:
            positions.append(p)

    yara_strings = []
    tokens = [f"{lcs[0]:02x}"]
    for i in range(len(lcs) - 1):
        contiguous_in_all = all(p[i+1] == p[i] + 1 for p in positions)
        if not contiguous_in_all:
            gaps = [p[i+1] - p[i] for p in positions]
            gap_min = min(gaps)
            gap_max = max(gaps)
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


def build_yara_rule_text(family: str, yara_strings: list[str], time_to_build: float) -> str:
    strings_block = ""
    for i, s in enumerate(yara_strings):
        strings_block += f"        $s{i} = {s}\n"
    reported_time_to_build = f"{round(time_to_build, 2)} sec" if time_to_build < 60.0 else f"{round(time_to_build/60.0, 2)} min"
    return f"""rule {family}
{{
    meta:
        family = "{family}"
        time_to_build = "{reported_time_to_build}"
    strings:
{strings_block}
    condition:
        any of them
}}"""


def main():
    ap = argparse.ArgumentParser(description="ABLATION A2 — Bounded gaps + Clustering, no filters, no median pair")
    ap.add_argument("family_dirpath", type=str)
    ap.add_argument("--truncate-bytes", type=int, default=TRUNCATE_BYTES_DEFAULT)
    ap.add_argument("-v", "--verbose", action="count", default=0)
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--batch-size", type=int, default=None)
    args = ap.parse_args()

    level = logging.WARNING if args.verbose == 0 else (logging.INFO if args.verbose == 1 else logging.DEBUG)
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)-5s | %(message)s")
    logger = logging.getLogger("LCS_A2")

    family_dirpath = args.family_dirpath
    if not os.path.isdir(family_dirpath):
        raise SystemExit(f"Not a directory: {family_dirpath}")
    family = os.path.basename(os.path.normpath(family_dirpath))

    try:
        start_time = monotonic()
        sequences = collect_samples(family_dirpath, args.truncate_bytes, logger)
        if args.batch_size:
            sequences = sequences[:args.batch_size]

        # ABLATION A2: clustering ACTIF
        clusters = cluster_samples(sequences, logger)

        all_yara_strings = []
        for cluster in clusters:
            cluster_sequences = [sequences[i] for i in cluster]
            # ABLATION A2: k-LCS progressif NW global (pas de paire médiane)
            if len(cluster_sequences) < 2:
                continue
            lcs = k_lcs(cluster_sequences, logger=logger, workers=args.workers)
            yara_strings = yara_format_lcs(lcs, cluster_sequences)
            yara_strings = filter_yara_strings(yara_strings)  # désactivé en A2
            all_yara_strings.extend(yara_strings)

        time_to_build = monotonic() - start_time

        if not all_yara_strings:
            print(f"No signature for {family}")
        else:
            rule_text = build_yara_rule_text(family, all_yara_strings, time_to_build)
            family_signatures_dirpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures_ablation", "A2", family)
            os.makedirs(family_signatures_dirpath, exist_ok=True)
            output_filepath = os.path.join(family_signatures_dirpath, f"{family}.yar")
            with open(output_filepath, 'w') as file:
                file.write(rule_text)
            print(f"Wrote signature to {output_filepath}")

    except KeyboardInterrupt:
        logger.error("Interrupted.")
        sys.exit(1)

if __name__ == "__main__":
    main()
