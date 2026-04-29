"""
Fast LCS to YARA Signature Generator.
Uses edlib for C-backed Levenshtein distance and global alignment pathing.
Implements a greedy pairwise reduction with multiprocessing and VxSig-style gap formatting.
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
MAX_GAP = 20 # gap borné : si gap_max > MAX_GAP, on coupe la string
MIN_BLOCK = 8 # taille minimale d'un bloc pour être gardé (bytes)

CLUSTER_SAMPLE_BYTES = 10_000# bytes utilisés pour le clustering
CLUSTER_THRESHOLD=0.3 #seuil si dist_normalisée < 0.30:les 2 samples sont dans le meme cluster
MAX_STRINGS = 20

def read_truncated(sample_filepath: str, limit: int) -> bytes:
    """Reads a file up to a specified byte limit."""
    with open(sample_filepath, 'rb') as file:
        return file.read(limit)



def worker_init():
    """Instructs child processes to ignore SIGINT (Ctrl+C) so the parent can handle it."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)



# Could also be parallelized but clearly is not the main bottleneck
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

def _cluster_dist_task(args: Tuple[int, int, bytes, bytes]) -> Tuple[int, int, float]:
    """Worker multiprocessing : distance normalisée sur court préfixe."""
    i, j, a, b = args
    d = edlib.align(a, b, mode="NW", task="distance")["editDistance"]
    norm = d / max(len(a), len(b)) if max(len(a), len(b)) > 0 else 0.0
    return (i, j, norm)



def cluster_samples(sequences: list[bytes], threshold: float,logger: logging.Logger, pool=None) -> list[list[int]]:
    n     = len(sequences)
    short = [s[:CLUSTER_SAMPLE_BYTES] for s in sequences]

    tasks = [(i, j, short[i], short[j])
             for i in range(n) for j in range(i+1, n)]

    if pool and tasks:
        results = list(pool.imap(_cluster_dist_task, tasks, chunksize=1))
    else:
        results = [_cluster_dist_task(t) for t in tasks]

    # Union-Find
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        parent[find(x)] = find(y)

    for i, j, norm_dist in results:
        if norm_dist < threshold:
            union(i, j)

    # Regrouper par racine
    clusters: Dict[int, list[int]] = {}
    for idx in range(n):
        root = find(idx)
        clusters.setdefault(root, []).append(idx)

    result = list(clusters.values())
    logger.info(f"Clustering → {len(result)} cluster(s) depuis {n} séquences "
                f"(threshold={threshold})")
    for k, cl in enumerate(result):
        logger.info(f"  cluster {k} : {len(cl)} séquences → indices {cl}")
    return result



def pair_lcs(a: bytes, b: bytes) -> bytes:
    """
    Computes a common subsequence of a pair of sequences using edlib's extended CIGAR (Compact Idiosyncratic Gapped Alignment Report) path.
    Extracts only exact match runs ('=') from a Needleman-Wunsch global alignment.
    """
    res = edlib.align(a, b, mode="NW", task="path")
    cigar = res["cigar"]
    if cigar is None:
        return b""

    i = j = 0 # indexes that will respectively track the current position in the sequences A and B
    output = bytearray()
    run = 0
    
    for ch in cigar:
        if ch.isdigit(): # parsing the numbers
            run = run * 10 + (ord(ch) - 48)
            continue
        if run == 0:
            run = 1
            
        if ch == "=": # both sequences share the exact same bytes for the next [run] length
            output.extend(a[i:i+run])
            i += run
            j += run
        elif ch in ("X", "M"): # processed bytes align at this position but they are different
            i += run
            j += run
        elif ch == "I": # processed bytes exist in B but not in A
            j += run
        elif ch == "D": # processed bytes exist in A but not in B
            i += run
            
        run = 0
        
    return bytes(output)



def _compute_edit_distance_task(args: Tuple[int, int, bytes, bytes]) -> Tuple[int, int, int]:
    """Multiprocessing worker function for Levenshtein distance calculation."""
    i, j, a_bytes, b_bytes = args
    dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")["editDistance"]
    return (dist, i, j)



def build_all_distances(items: Dict[int, bytes], active_ids: set[int], pool=None) -> Dict[Tuple[int,int], int]:
    """Generates a fresh pairwise distance min-heap for active sequences. O(N^2)"""

    tasks = [(i, j, items[i], items[j])
             for ix, i in enumerate(active_ids)
             for j in active_ids[ix+1:]]

    if pool and tasks:
        raw = list(pool.imap(_compute_edit_distance_task, tasks, chunksize=1))
    else:
        raw = [_compute_edit_distance_task(t) for t in tasks]

    return {(min(i,j), max(i,j)): d for d, i, j in raw}



def build_distance_heap(items: Dict[int, bytes], active_ids: set[int], pool=None) -> list[Tuple[int, int, int]]:
    """Generates a fresh pairwise distance min-heap for active sequences."""
    heap: list[Tuple[int, int, int]] = []
    ids = list(active_ids)
    tasks: List[Tuple[int, int, bytes, bytes]] = []
    for ix in range(len(ids)):
        i = ids[ix]
        for jx in range(ix + 1, len(ids)):
            j = ids[jx]
            tasks.append((i, j, items[i], items[j]))
    if pool and tasks:
        for dist, i, j in pool.imap(_compute_edit_distance_task, tasks, chunksize=1):
            heap.append((dist, i, j))
    else:
        for i, j, a_bytes, b_bytes in tasks:
            dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")['editDistance']
            heap.append((dist, i, j))
    heapq.heapify(heap)
    return heap




def k_lcs(sequences: list[bytes], *, logger: logging.Logger, workers: int) -> bytes:
    """
    Reduces [k] byte sequences to a single common subsequence using a 
    greedy min-heap approach. Iteratively merges the closest pair in-place.
    """
    if not sequences:
        return b""

    # Dictionary mapping sequence ID directly to its byte payload
    items: Dict[int, bytes] = {id: seq for id, seq in enumerate(sequences)}
    active = set(items.keys())
    
    pool = None
    if workers:
        pool = Pool(processes=workers, initializer=worker_init)

    step = 1
    try:
        # Loop until only one sequence (i.e., the final LCS) is left
        while len(active) > 1:
            # (Re)Build a fresh min-heap containing only valid active distances
            heap = build_distance_heap(items, active, pool)
            
            # Get the closest pair (eventual ties are resolved by picking the smallest IDs)
            dist, i, j = heapq.heappop(heap)
            
            logger.info(f"[step {step}] closest pair: ({i},{j}) |A|={len(items[i])} |B|={len(items[j])} d={dist}")

            # Compute LCS
            t0 = monotonic()
            lcs_ij = pair_lcs(items[i], items[j])
            logger.info(f"[step {step}] edlib LCS -> |LCS|={len(lcs_ij)} in {monotonic() - t0:.2f}s")

            # Overwrite the sequence with the smaller ID, delete the larger one
            keep_id, drop_id = (i, j) if i < j else (j, i)
            items[keep_id] = lcs_ij
            active.remove(drop_id)
            del items[drop_id]
            
            # Filter remaining sequences in-place (removing all bytes not present in the pair LCS found)
            if lcs_ij:
                allowed = set(lcs_ij)
                for k in active:
                    if k != keep_id:
                        items[k] = bytes(b for b in items[k] if b in allowed)

            step += 1

    except KeyboardInterrupt:
            # Catch the keyboard interrupt and terminate the pool instantly
            if pool is not None:
                pool.terminate() # Instantly kills workers without waiting for tasks to finish
                pool.join()
                pool = None      # Prevents the finally block from throwing an error
            raise # Re-raise the exception to be caught in main()

    finally:
        if pool is not None:
            pool.close() # End of the parallelizable part
            pool.join()  # Wait until all workers have finished their task

    last_id = next(iter(active)) # cleanly retrieving the last remaining item in active set
    return items[last_id]




def k_lcs_median(sequences: list[bytes], *,logger: logging.Logger, pool=None) -> bytes:
    if not sequences:
        return b""
    if len(sequences) == 1:
        return sequences[0]

    items: Dict[int, bytes] = {idx: s for idx, s in enumerate(sequences)}
    originals: Dict[int, bytes] = {idx: s for idx, s in enumerate(sequences)}  # ← ajouter
    active = list(items.keys())

    step = 1
    try:
        while len(active) > 1:
            # Recalculer toutes les distances sur l'ensemble actif courant
            dist_map = build_all_distances(items, active, pool)

            # Pour chaque séquence, calculer sa distance médiane aux autres
            median_scores: Dict[int, float] = {}
            for i in active:
                dists_i = [dist_map[(min(i,j), max(i,j))]
                        for j in active if j != i]
                median_scores[i] = statistics.median(dists_i) if dists_i else 0.0

            # Séquence la plus centrale = médiane minimale
            i_star = min(active, key=lambda i: median_scores[i])

            # Plus proche voisin de i_star
            j_star = min(
                (j for j in active if j != i_star),
                key=lambda j: dist_map[(min(i_star,j), max(i_star,j))]
            )

            d_star = dist_map[(min(i_star, j_star), max(i_star, j_star))]
            logger.info(
                f"[step {step}] central: {i_star} "
                f"(median_dist={median_scores[i_star]:.0f}), "
                f"merge avec {j_star} d={d_star} "
                f"|A|={len(items[i_star])} |B|={len(items[j_star])}"
            )

            # Calcul LCS
            t0 = monotonic()
            lcs_ij = pair_lcs(items[i_star], items[j_star])
            logger.info(f"[step {step}] LCS → {len(lcs_ij)} bytes en {monotonic()-t0:.2f}s")

            # Merger : garder i_star, supprimer j_star
            items[i_star] = lcs_ij
            active.remove(j_star)
            del items[j_star]

            # Filtrer les séquences restantes
            if lcs_ij:
                allowed = set(lcs_ij)
                for k in active:
                    if k != i_star:
                        items[k] = bytes(b for b in items[k] if b in allowed)

            step += 1

    except KeyboardInterrupt:
        raise

    return items[active[0]]





def yara_format_lcs(lcs: bytes, sequences: list[bytes], *, bytes_per_line: int = 24, max_gap: int = MAX_GAP, min_block: int = MIN_BLOCK) -> list[str]:
    """
    Formats raw bytes into a YARA hex string.
    Inserts '[-]' wildcards only between non-contiguous sequences.
    """
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

    def flush_block(block_tokens: list[str]) -> str | None:
        byte_count = sum(1 for t in block_tokens if not t.startswith("["))
        if byte_count < min_block:
            return None
        out_lines, line, count = [], [], 0
        for t in block_tokens:
            line.append(t)
            count += 1
            if count >= bytes_per_line and t is not block_tokens[-1]:
                out_lines.append(" ".join(line))
                line = []
                count = 0
        if line:
            out_lines.append(" ".join(line))
        return "{ " + " \n        ".join(out_lines) + " }" if len(out_lines) > 1 else "{ " + out_lines[0] + " }"

    if not lcs:
        return []

    positions: list[list[int]] = []
    for sequence in sequences:
        pos = sequence_lcs_bytes_positions(sequence, lcs)
        if pos is not None:
            positions.append(pos)

    if not positions:
        return []

    yara_strings: list[str] = []
    current_block: list[str] = [f"{lcs[0]:02x}"]

    for i in range(len(lcs) - 1):
        contiguous_in_all = all(p[i+1] == p[i] + 1 for p in positions)

        if contiguous_in_all:
            current_block.append(f"{lcs[i+1]:02x}")
        else:
            gaps = [p[i+1] - p[i] - 1 for p in positions]
            gap_min = min(gaps)
            gap_max = max(gaps)

            if gap_max > max_gap:
                # Trop grand → couper ici
                result = flush_block(current_block)
                if result:
                    yara_strings.append(result)
                current_block = [f"{lcs[i+1]:02x}"]
            else:
                # Gap borné
                gap_token = f"[{gap_min}]" if gap_min == gap_max else f"[{gap_min}-{gap_max}]"
                if gap_min > 0 or gap_min != gap_max:
                    current_block.append(gap_token)
                current_block.append(f"{lcs[i+1]:02x}")

    result = flush_block(current_block)
    if result:
        yara_strings.append(result)

    return yara_strings


def build_yara_rule_text(family: str, lcs: bytes, sequences: list[bytes], time_to_build: float) -> str:
    """Constructs YARA rule with multiple bounded strings and 'any of them' condition."""
    MAX_STRINGS = 20  

    yara_strings = yara_format_lcs(lcs, sequences)
    
    # Garder seulement les N strings les plus longues
    if len(yara_strings) > MAX_STRINGS:
        yara_strings = sorted(yara_strings, key=len, reverse=True)[:MAX_STRINGS]
    
    reported_time_to_build = f"{round(time_to_build, 2)} sec" if time_to_build < 60.0 else f"{round(time_to_build/60.0, 2)} min"

    if not yara_strings:
        strings_block = '        $s0 = { ' + ' '.join(f"{b:02x}" for b in lcs[:16]) + ' }'
        condition = "$s0"
    else:
        strings_block = "\n".join(f"        $s{idx} = {s}" for idx, s in enumerate(yara_strings))
        condition = "any of them" if len(yara_strings) > 1 else "$s0"

    return f"""rule {family}
{{
    meta:
        family = "{family}"
        nb_samples = {len(sequences)}
        lcs_length = {len(lcs)}
        nb_strings = {len(yara_strings)}
        max_gap = {MAX_GAP}
        time_to_build = "{reported_time_to_build}"
    strings:
{strings_block}
    condition:
        {condition}
}}"""






def run_pipeline(sequences: list[bytes], family: str,time_to_build: float, logger: logging.Logger,pool=None) -> str:
    
    clusters = cluster_samples(sequences, CLUSTER_THRESHOLD, logger, pool)

    all_strings: list[str] = []
    for k, cluster_indices in enumerate(clusters):
        cluster_seqs = [sequences[i] for i in cluster_indices]
        logger.info(f"Cluster {k}: LCS sur {len(cluster_seqs)} séquences")

        if len(cluster_seqs) == 1:
            lcs = cluster_seqs[0][:64]
            logger.info(f"Cluster {k}: séquence unique, ancre de {len(lcs)} bytes")
        else:
            lcs = k_lcs_median(cluster_seqs, logger=logger, pool=pool)
            logger.info(f"Cluster {k}: LCS = {len(lcs)} bytes")

        strings = yara_format_lcs(lcs, cluster_seqs, max_gap=MAX_GAP, min_block=MIN_BLOCK)
        logger.info(f"Cluster {k}: {len(strings)} string(s) YARA")
        all_strings.extend(strings)

    if len(all_strings) > MAX_STRINGS:
        all_strings = sorted(all_strings, key=len, reverse=True)[:MAX_STRINGS]

    reported = (f"{round(time_to_build, 2)} sec" if time_to_build < 60
                else f"{round(time_to_build/60, 2)} min")

    if not all_strings:
        return ""

    strings_block = "\n".join(
        f"        $s{i} = {s}" for i, s in enumerate(all_strings)
    )
    condition = "any of them" if len(all_strings) > 1 else "$s0"

    return f"""rule {family}
{{
    meta:
        family = "{family}"
        nb_samples = {len(sequences)}
        nb_clusters = {len(clusters)}
        nb_strings = {len(all_strings)}
        max_gap = {MAX_GAP}
        cluster_threshold = "{CLUSTER_THRESHOLD}"
        pair_selection = "median"
        time_to_build = "{reported}"
    strings:
{strings_block}
    condition:
        {condition}
}}"""






def main():
    global MAX_GAP, MIN_BLOCK, MAX_STRINGS

    ap = argparse.ArgumentParser(description="LCS YARA generator — clustering + médiane")
    ap.add_argument("family_dirpath", type=str)
    ap.add_argument("--truncate-bytes", type=int, default=TRUNCATE_BYTES_DEFAULT)
    ap.add_argument("--batch-size", type=int, default=10,
                    help="Nombre de fichiers d'entraînement (défaut: 10). "
                         "Varier pour tester l'effet train!=test : 10, 20, 30, 40, 50")
    ap.add_argument("--max-gap",     type=int,   default=MAX_GAP)
    ap.add_argument("--min-block",   type=int,   default=MIN_BLOCK)
    ap.add_argument("--max-strings", type=int,   default=MAX_STRINGS)
    ap.add_argument("--workers",     type=int,   default=0)
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args()

    MAX_GAP     = args.max_gap
    MIN_BLOCK   = args.min_block
    MAX_STRINGS = args.max_strings

    level = (logging.WARNING if args.verbose == 0
             else logging.INFO if args.verbose == 1
             else logging.DEBUG)
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)-5s | %(message)s")
    logger = logging.getLogger("LCS")

    if not os.path.isdir(args.family_dirpath):
        raise SystemExit(f"Not a directory: {args.family_dirpath}")

    family = os.path.basename(os.path.normpath(args.family_dirpath))
    logger.info(f"Family: {family} | batch_size={args.batch_size}")

    pool = None
    if args.workers:
        pool = Pool(processes=args.workers, initializer=worker_init)

    try:
        t0 = monotonic()

        # Charger les N premiers fichiers (batch_size) → train set
        all_files = sorted(os.listdir(args.family_dirpath))
        selected  = all_files[:args.batch_size]
        logger.info(f"Utilisation de {len(selected)}/{len(all_files)} fichiers (batch_size={args.batch_size})")
        sequences = []
        for fname in selected:
            fpath = os.path.join(args.family_dirpath, fname)
            sequences.append(read_truncated(fpath, args.truncate_bytes))

        rule_text  = run_pipeline(sequences, family, monotonic() - t0, logger, pool)
        time_total = monotonic() - t0

        if not rule_text:
            logger.error("Aucune string YARA produite — règle non écrite.")
            raise SystemExit(1)

        out_dir  = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "signatures_v2", family)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"{family}.yar")
        with open(out_path, 'w') as f:
            f.write(rule_text)
        print(f"Wrote signature to {out_path}  ({time_total:.1f}s total)")

    except KeyboardInterrupt:
        logger.error("Interrompu.")
        sys.exit(1)
    finally:
        if pool:
            pool.close()
            pool.join()


if __name__ == "__main__":
    main()
