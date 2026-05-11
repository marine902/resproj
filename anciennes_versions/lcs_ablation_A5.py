"""
ABLATION A5 — Toutes les améliorations actives (équivalent à lcs_v1.py).
Améliorations actives : 1 + 2 + 3 + 4 + 5 + 6
Ce fichier est identique à lcs_v1.py — il sert de point de comparaison final
pour l'étude d'ablation, avec les signatures écrites dans signatures_ablation/A5/.

Différence avec lcs_v1.py : les signatures sont écrites dans signatures_ablation/A5/
au lieu de signatures/, pour ne pas écraser les résultats de production.
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
    """Reads a file up to a specified byte limit."""
    with open(sample_filepath, 'rb') as file:
        return file.read(limit)

def worker_init():
    """Instructs child processes to ignore SIGINT (Ctrl+C) so the parent can handle it."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def collect_samples(samples_dirpath: str, limit: int, logger: logging.Logger) -> list[bytes]:
    """Loads and truncates all files within a specified directory."""
    samples_filepaths = [os.path.join(samples_dirpath, filename) for filename in sorted(os.listdir(samples_dirpath))]
    if not samples_filepaths:
        raise SystemExit(f"No files found in {samples_dirpath}")
    logger.info(f"Found {len(samples_filepaths)} files in '{samples_dirpath}'. Reading up to {limit} bytes each...")
    sequences: list[bytes] = []
    for idx, filepath in enumerate(samples_filepaths, 1):
        t0 = monotonic()
        data = read_truncated(filepath, limit)
        dt = monotonic() - t0
        logger.debug(f"[{idx}/{len(samples_filepaths)}] {os.path.basename(filepath)}: read {len(data)} bytes in {dt:.2f}s")
        sequences.append(data)
    logger.info(f"Loaded {len(sequences)} byte sequences.")
    return sequences

def pair_lcs(a: bytes, b: bytes) -> bytes:
    """
    Computes a common subsequence of a pair of sequences using edlib's extended CIGAR path.
    Extracts only exact match runs ('=') from a Needleman-Wunsch global alignment.
    """
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
    """Multiprocessing worker function for Levenshtein distance calculation."""
    i, j, a_bytes, b_bytes = args
    dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")["editDistance"]
    return (dist, i, j)

def build_distance_heap(items: Dict[int, bytes], active_ids: set[int], pool=None, logger: logging.Logger = None) -> list[Tuple[int, int, int]]:
    """Generates a fresh pairwise distance min-heap for active sequences. O(N^2)"""
    heap: list[Tuple[int, int, int]] = []
    ids = list(active_ids)
    n = len(ids)
    tasks: List[Tuple[int, int, bytes, bytes]] = []
    for ix in range(n):
        i = ids[ix]
        for jx in range(ix + 1, n):
            j = ids[jx]
            tasks.append((i, j, items[i], items[j]))
    total = len(tasks)
    log_interval = max(1, total // 10)
    t_heap_start = monotonic()
    if logger:
        logger.info(f"  Building distance heap: {total} pairs to compute ({n} active sequences)...")
    if pool and tasks:
        for done, (dist, i, j) in enumerate(pool.imap(_compute_edit_distance_task, tasks, chunksize=4), 1):
            heap.append((dist, i, j))
            if logger and done % log_interval == 0:
                elapsed = monotonic() - t_heap_start
                eta = elapsed / done * (total - done)
                logger.info(f"  [{done}/{total} pairs | {done*100//total}% | elapsed {elapsed:.0f}s | ETA ~{eta:.0f}s]")
    else:
        for done, (i, j, a_bytes, b_bytes) in enumerate(tasks, 1):
            dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")['editDistance']
            heap.append((dist, i, j))
            if logger and done % log_interval == 0:
                elapsed = monotonic() - t_heap_start
                eta = elapsed / done * (total - done)
                logger.info(f"  [{done}/{total} pairs | {done*100//total}% | elapsed {elapsed:.0f}s | ETA ~{eta:.0f}s]")
    if logger:
        logger.info(f"  Heap built in {monotonic() - t_heap_start:.1f}s")
    heapq.heapify(heap)
    return heap


# AMÉLIORATION 2 ACTIVE: clustering Union-Find
cluster_sample_bytes = 10000
cluster_threshold = 0.8

def cluster_samples(sequences: list[bytes], logger: logging.Logger):
    '''Regroup the sequences in clusters via Union-Find (Amélioration 2).'''
    n = len(sequences)
    prefix = [s[:cluster_sample_bytes] for s in sequences]
    parent = []
    for i in range(n):
        parent.append(i)

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

    if all_distances:
        max_distance = max(all_distances.values())
    else:
        max_distance = 0
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
    logger.info(f"Clustering results:{len(result)} clusters formed")
    return result


def k_lcs(sequences: list[bytes], *, logger: logging.Logger, workers: int) -> bytes:
    """Reduces [k] byte sequences to a single common subsequence using a greedy min-heap approach."""
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
            logger.info(f"[step {step}/{total_steps}] {len(active)} sequences remaining — rebuilding distance heap...")
            heap = build_distance_heap(items, active, pool, logger=logger)
            dist, i, j = heapq.heappop(heap)
            logger.info(f"[step {step}/{total_steps}] closest pair: ({i},{j}) |A|={len(items[i])} |B|={len(items[j])} d={dist}")
            t0 = monotonic()
            lcs_ij = pair_lcs(items[i], items[j])
            logger.info(f"[step {step}] edlib LCS -> |LCS|={len(lcs_ij)} in {monotonic() - t0:.2f}s")
            keep_id, drop_id = (i, j) if i < j else (j, i)
            items[keep_id] = lcs_ij
            active.remove(drop_id)
            del items[drop_id]
            if lcs_ij:
                allowed = set(lcs_ij)
                for k in active:
                    if k != keep_id:
                        items[k] = bytes(b for b in items[k] if b in allowed)
            logger.info(f"[step {step}/{total_steps}] done — {len(active)} sequences remaining")
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


# AMÉLIORATION 3 ACTIVE: filtres de qualité
min_block_bytes = 8
min_unique_ratio = 0.25
min_sequence_length = 20
max_sequence_ratio = 0.85
max_null_ratio = 0.4

def clean_block(tokens: list[str]) -> list[str] | None:
    '''Filter for null bytes, PE header, block too small.'''
    hex_tokens = [t for t in tokens if not t.startswith("[")]
    if len(hex_tokens) < min_block_bytes:
        return None
    unique_bytes = set()
    for t in hex_tokens:
        unique_bytes.add(t)
    unique_ratio = len(unique_bytes) / len(hex_tokens)
    if unique_ratio < min_unique_ratio:
        return None
    byte_vals = []
    for t in hex_tokens:
        byte_vals.append(int(t, 16))
    seq_count = 0
    for i in range(len(byte_vals)-1):
        if byte_vals[i+1]-byte_vals[i] == 1:
            seq_count += 1
    if len(byte_vals) > min_sequence_length and seq_count/(len(byte_vals)-1) > max_sequence_ratio:
        return None
    null_count = 0
    for t in hex_tokens:
        if t == "00":
            null_count += 1
    null_ratio = null_count / len(hex_tokens)
    if null_ratio > max_null_ratio:
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
        null_ratio = sum(1 for t in bytes_only if t == "00") / len(bytes_only)
        if null_ratio > 0.5:
            continue
        unique_ratio = len(set(bytes_only)) / len(bytes_only)
        if unique_ratio < 0.10:
            continue
        byte_vals = [int(t, 16) for t in bytes_only]
        differences = [byte_vals[i+1] - byte_vals[i] for i in range(len(byte_vals)-1)]
        if len(differences) > 20 and sum(1 for d in differences if d == 1) / len(differences) > 0.85:
            continue
        filtered.append(s)
    return filtered


# Paramètres
min_block_size = 16
max_gap_size = 50
max_block_bytes = 500
max_strings_per_cluster = 20


# AMÉLIORATION 6 ACTIVE: construction YARA depuis CIGAR
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


# AMÉLIORATION 5 ACTIVE: alignement local par fenêtre glissante HW
local_window_size = 1024
local_window_step = 512
local_min_match_ratio = 0.4

def local_align_and_build_yara_strings(a: bytes, b: bytes, window_size: int = local_window_size, window_step: int = local_window_step, min_match_ratio: float = local_min_match_ratio) -> list[str]:
    strings = []
    seen_offsets = set()
    for start in range(0, len(a)-window_size+1, window_step):
        window = a[start:start+window_size]
        try:
            result = edlib.align(window, b, mode="HW", task="path")
        except Exception:
            continue
        if result["editDistance"] < 0:
            continue
        match_ratio = 1.0 - result["editDistance"]/window_size
        if match_ratio < min_match_ratio:
            continue
        localisations = result.get("locations")
        if not localisations:
            continue
        b_start, b_end = localisations[0]
        if b_start in seen_offsets:
            continue
        seen_offsets.add(b_start)
        b_region = b[b_start:b_end+1]
        new_strings = align_and_build_yara_strings(window, b_region)
        strings.extend(new_strings)
        if len(strings) >= max_strings_per_cluster:
            break
    return strings


def yara_format_lcs(lcs: bytes, sequences: list[bytes], *, bytes_per_line: int = 24) -> list[str]:
    """Formats raw bytes into a YARA hex string with bounded [min-max] gaps."""
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
    positions: list[list[int]] = []
    for sequence in sequences:
        sequence_positions = sequence_lcs_bytes_positions(sequence, lcs)
        if sequence_positions is not None:
            positions.append(sequence_positions)
    yara_strings = []
    tokens: list[str] = [f"{lcs[0]:02x}"]
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
    """Constructs YARA rule string corresponding to the malware family signature."""
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
    ap = argparse.ArgumentParser(description="ABLATION A5 — All improvements active (= lcs_v1.py)")
    ap.add_argument("family_dirpath", type=str)
    ap.add_argument("--truncate-bytes", type=int, default=TRUNCATE_BYTES_DEFAULT)
    ap.add_argument("-v", "--verbose", action="count", default=0)
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--batch-size", type=int, default=None)
    args = ap.parse_args()

    level = logging.WARNING if args.verbose == 0 else (logging.INFO if args.verbose == 1 else logging.DEBUG)
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)-5s | %(message)s")
    logger = logging.getLogger("LCS_A5")

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

            # AMÉLIORATION 4+5 ACTIVES: paire médiane + alignement local HW
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
                _, i_medianne, j_medianne = best_pair
                yara_strings = local_align_and_build_yara_strings(
                    cluster_sequences[i_medianne], cluster_sequences[j_medianne]
                )
                yara_strings = filter_yara_strings(yara_strings)

            all_yara_strings.extend(yara_strings)

        time_to_build = monotonic() - start_time

        if not all_yara_strings:
            logger.warning(f"No YARA strings generated for {family} — skipping")
            print(f"No signature for {family}")
        else:
            rule_text = build_yara_rule_text(family, all_yara_strings, time_to_build)
            # ABLATION A5: écriture dans signatures_ablation/A5/ (pas signatures/)
            out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures_ablation", "A5", family)
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, f"{family}.yar")
            with open(out_path, 'w') as file:
                file.write(rule_text)
            print(f"Wrote signature to {out_path}")

    except KeyboardInterrupt:
        logger.error("Execution interrupted by user (Ctrl+C). Shutting down...")
        sys.exit(1)

if __name__ == "__main__":
    main()
