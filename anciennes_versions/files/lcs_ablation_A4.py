"""
ABLATION A4 — Gaps bornés + Clustering + Filtres + Paire médiane (NW global).
Améliorations actives : 1 + 2 + 3 + 4 (+ 6 via align_and_build_yara_strings)
Améliorations désactivées :
    - Alignement local (mode HW fenêtre glissante désactivé — NW global uniquement)
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
    sequences: list[bytes] = []
    for filepath in samples_filepaths:
        sequences.append(read_truncated(filepath, limit))
    logger.info(f"Loaded {len(sequences)} byte sequences.")
    return sequences

def _compute_edit_distance_task(args):
    i, j, a_bytes, b_bytes = args
    dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")["editDistance"]
    return (dist, i, j)


# ABLATION A4: clustering ACTIF
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


# ABLATION A4: filtres de qualité ACTIFS
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


# ABLATION A4: align_and_build_yara_strings ACTIF (Amélioration 6, construction depuis CIGAR)
def align_and_build_yara_strings(a: bytes, b: bytes, max_block_bytes: int = max_block_bytes) -> list[str]:
    if len(a) > len(b):
        a, b = b, a
    result = edlib.align(a, b, mode="NW", task="path")
    cigar = result["cigar"]
    if cigar is None:
        return []
    operations = []
    run = 0
    for ch in cigar:
        if ch.isdigit():
            run = run * 10 + (ord(ch) - 48)
        else:
            if run == 0:
                run = 1
            operations.append((ch, run))
            run = 0
    strings = []
    current_string = []
    current_len = 0
    in_gap = False
    gap_min = 0
    gap_max = 0
    i = 0

    def flush_gap():
        nonlocal in_gap, gap_min, gap_max
        if in_gap:
            current_string.append("["+str(gap_min)+"-"+str(gap_max)+"]")
            in_gap = False
            gap_min = 0
            gap_max = 0

    def flush_block():
        nonlocal current_string, current_len, in_gap, gap_min, gap_max
        if in_gap:
            in_gap = False; gap_min = 0; gap_max = 0
        if current_len >= min_block_size:
            tokens = current_string[:]
            while tokens and tokens[0][0] == "[":
                tokens.pop(0)
            while tokens and tokens[-1][0] == "[":
                tokens.pop()
            byte_count = sum(1 for t in tokens if t[0] != "[")
            if byte_count >= min_block_size:
                strings.append("{ " + " ".join(tokens) + " }")
        current_string.clear()
        current_len = 0

    for operation, count in operations:
        if i >= len(a):
            break
        if operation == "=":
            flush_gap()
            safe = min(count, len(a)-i)
            remaining_bytes = safe
            position = i
            while remaining_bytes > 0:
                space = max_block_bytes - current_len
                chunk = min(space, remaining_bytes)
                for k in range(chunk):
                    current_string.append(f"{a[position+k]:02x}")
                current_len += chunk
                position += chunk
                remaining_bytes -= chunk
                if current_len >= max_block_bytes:
                    flush_block()
            i += safe
        elif operation == "X":
            safe = min(count, len(a)-i)
            if safe > max_gap_size:
                flush_block()
            else:
                if not in_gap:
                    in_gap = True; gap_min = safe; gap_max = safe
                else:
                    gap_min += safe; gap_max += safe
            i += safe
        elif operation == "D":
            safe = min(count, len(a)-i)
            if safe > max_gap_size:
                flush_block()
            else:
                if not in_gap:
                    in_gap = True; gap_min = 0; gap_max = safe
                else:
                    gap_max += safe
            i += safe
        elif operation == "I":
            if count > max_gap_size:
                flush_block()
            else:
                if not in_gap:
                    in_gap = True; gap_min = 0; gap_max = count
                else:
                    gap_max += count
    flush_block()
    return strings


def build_yara_rule_text(family, yara_strings, time_to_build):
    strings_block = "".join(f"        $s{i} = {s}\n" for i, s in enumerate(yara_strings))
    rt = f"{round(time_to_build, 2)} sec" if time_to_build < 60 else f"{round(time_to_build/60, 2)} min"
    return f"rule {family}\n{{\n    meta:\n        family = \"{family}\"\n        time_to_build = \"{rt}\"\n    strings:\n{strings_block}\n    condition:\n        any of them\n}}"


def main():
    ap = argparse.ArgumentParser(description="ABLATION A4 — Bounded gaps + Clustering + Filters + Median pair (NW global)")
    ap.add_argument("family_dirpath", type=str)
    ap.add_argument("--truncate-bytes", type=int, default=TRUNCATE_BYTES_DEFAULT)
    ap.add_argument("-v", "--verbose", action="count", default=0)
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--batch-size", type=int, default=None)
    args = ap.parse_args()

    level = logging.WARNING if args.verbose == 0 else (logging.INFO if args.verbose == 1 else logging.DEBUG)
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)-5s | %(message)s")
    logger = logging.getLogger("LCS_A4")

    family_dirpath = args.family_dirpath
    if not os.path.isdir(family_dirpath):
        raise SystemExit(f"Not a directory: {family_dirpath}")
    family = os.path.basename(os.path.normpath(family_dirpath))

    try:
        start_time = monotonic()
        sequences = collect_samples(family_dirpath, args.truncate_bytes, logger)
        if args.batch_size:
            sequences = sequences[:args.batch_size]

        clusters = cluster_samples(sequences, logger)

        all_yara_strings = []
        for cluster in clusters:
            cluster_sequences = [sequences[i] for i in cluster]

            # ABLATION A4: paire médiane ACTIVE, mode NW global (pas HW local)
            pairs = []
            for i in range(len(cluster_sequences)):
                for j in range(i+1, len(cluster_sequences)):
                    d = edlib.align(cluster_sequences[i][:cluster_sample_bytes],
                                    cluster_sequences[j][:cluster_sample_bytes],
                                    mode="NW", task="distance")["editDistance"]
                    pairs.append((d, i, j))

            if len(pairs) == 0:
                yara_strings = []
            else:
                medianne = statistics.median([d for d, i, j in pairs])
                best_pair = min(pairs, key=lambda x: abs(x[0]-medianne))
                _, i_med, j_med = best_pair
                # ABLATION A4: alignement NW global (pas local HW)
                yara_strings = align_and_build_yara_strings(
                    cluster_sequences[i_med], cluster_sequences[j_med]
                )
                yara_strings = filter_yara_strings(yara_strings)

            all_yara_strings.extend(yara_strings)

        time_to_build = monotonic() - start_time

        if not all_yara_strings:
            print(f"No signature for {family}")
        else:
            rule_text = build_yara_rule_text(family, all_yara_strings, time_to_build)
            out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures_ablation", "A4", family)
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
