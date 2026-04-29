"""
Fast LCS to YARA Signature Generator.
Uses edlib for C-backed Levenshtein distance and global alignment pathing.
Implements a greedy pairwise reduction with multiprocessing and VxSig-style gap formatting.


improvements:
1: bounded gaps [min-max] instead of unbounded [-]
2: clustering (Union-Find) before alignment to handle heterogeneous families
3: multiple YARA strings per cluster (any of them) instead of a single string
4: forced block splitting every max_block_bytes to avoid oversized strings
5: null-byte filtering to remove non-discriminative strings
6: adaptive cluster threshold based on family homogeneity
7: adaptive truncation - retries with larger TRUNCATE_SIZE for no_strings families
8: local alignment mode (Smith-Waterman via edlib HW) for heterogeneous families

"""

from __future__ import annotations
import argparse
import logging
import heapq
import edlib
import gc
import os
import statistics
import zipfile
import csv
from time import monotonic,time
from typing import Dict, Tuple, List,Optional
from bisect import bisect_right
from multiprocessing import Pool


#parameters 
TRUNCATE_BYTES_DEFAULT= 200_000 #de base 1000000 mais reduced for RAM efficency (a revoir)
MIN_BLOCK_SIZE= 16 # Minimum bytes in a YARA hex block
MAX_GAP_SIZE= 50 # Gaps larger than this split the current block
PAIR_SAMPLE= 10_000# Bytes used for fast distance estimation in clustering
MAX_STRINGS_PER_CLUSTER = 20# Cap on YARA strings generated per cluster
MAX_BLOCK_BYTES= 500# Force block split every N bytes (avoids oversized strings)
CLUSTER_THRESHOLD= 0.8# Union-Find threshold as fraction of max pairwise distance


#adaptive truncation retry sizes
TRUNCATE_RETRY_SIZES= [500_000, 1_000_000]

#local alignment parameters
LOCAL_WINDOW_SIZE= 2_048 #sliding window size for local alignment (bytes)
LOCAL_WINDOW_STEP= 1_024 # step between windows (50% overlap)
LOCAL_MIN_MATCH_RATIO= 0.6# minimum fraction of matching bytes in a window to keep it



def read_truncated(sample_filepath: str, limit: int) -> bytes:
    """Reads a file up to a specified byte limit."""
    with open(sample_filepath, 'rb') as file:
        return file.read(limit)



# Could also be parallelized but clearly is not the main bottleneck
def collect_samples(samples_dirpath: str, limit: int, logger: logging.Logger) -> list[bytes]:
    """Loads and truncates all files within a specified directory."""
    samples_filepaths = [
        os.path.join(samples_dirpath, filename)
        for filename in sorted(os.listdir(samples_dirpath))
    ]
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


#for handling Kaggle/ colab zip datasets
def collect_samples_from_zip(zip_path: str,family_name: str,password: bytes,limit: int,max_samples: int = 10,) -> list[bytes]:
    #Loads samples from the zip
    samples = []
    prefix = f"dataset/malware/test/{family_name}/"
    with zipfile.ZipFile(zip_path, 'r') as z:
        all_files = [
            f for f in z.namelist()
            if f.startswith(prefix) and not f.endswith('/')
        ]
        for filepath in all_files[:max_samples]:
            with z.open(filepath, pwd=password) as f:
                samples.append(f.read(limit))
    return samples




def pair_lcs(a: bytes, b: bytes) -> bytes:
    """
    Computes a common subsequence of a pair of sequences using edlib's extended CIGAR (Compact Idiosyncratic Gapped Alignment Report) path.
    Extracts only exact match runs ('=') from a Needleman-Wunsch global alignment.
    """
    res = edlib.align(a, b, mode="NW", task="path")
    cigar = res["cigar"]
    if cigar is None:
        return b""

    i = j = 0 #index to track current position in sequences A and B
    output = bytearray()
    run = 0
    
    for ch in cigar:
        if ch.isdigit(): #parsing the numbers
            run = run * 10 + (ord(ch) - 48)
            continue
        if run == 0:
            run = 1
            
        if ch == "=": #both sequences share exact same bytes
            output.extend(a[i:i+run])
            i += run
            j += run
        elif ch in ("X", "M"): #bytes align at this position but they are different
            i += run
            j += run
        elif ch == "I": # bytes exist in B but not in A
            j += run
        elif ch == "D": #bytes exist in A but not in B
            i += run
            
        run = 0
        
    return bytes(output)



def _compute_edit_distance_task(args: Tuple[int, int, bytes, bytes]) -> Tuple[int, int, int]:
    """Multiprocessing worker function for Levenshtein distance calculation."""
    i, j, a_bytes, b_bytes = args
    dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")["editDistance"]
    return (dist, i, j)



def build_distance_heap(items: Dict[int, bytes], active_ids: set[int], pool=None) -> list[Tuple[int, int, int]]:
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

    if pool and tasks:
        for dist, i, j in pool.imap(_compute_edit_distance_task, tasks, chunksize=1):
            heap.append((dist, i, j))
    else:
        for i, j, a_bytes, b_bytes in tasks:
            dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")['editDistance']
            heap.append((dist, i, j))

    heapq.heapify(heap)
    return heap



def adaptive_threshold(distances: list[int], logger: Optional[logging.Logger] = None) -> float:
    """
    Computes a family-specific cluster threshold based on distance dispersion
    CV = std(distances) / mean(distances)
    threshold_ratio = clip(0.9 - 0.4 * CV, 0.4, 0.9)

    - low CV  (homogeneous family, e.g. daws)  → high threshold (merge easily)
    - high CV (heterogeneous family, e.g. jaik) → low threshold (keep clusters tight)
    
    Intuition:
      CV ≈ 0  (all samples equidistant, homogeneous) → threshold_ratio = 0.9
      CV ≈ 1  (high dispersion, heterogeneous)        → threshold_ratio = 0.5
      CV > 1  (extreme dispersion)                    → threshold_ratio = 0.4 (floor)
    """
    if len(distances) < 2:
        return CLUSTER_THRESHOLD

    mean_d = statistics.mean(distances)
    if mean_d == 0:
        return CLUSTER_THRESHOLD

    cv = statistics.stdev(distances) / mean_d
    ratio = max(0.4, min(0.9, 0.9 - 0.4 * cv))

    if logger:
        logger.info(f"Adaptive threshold: mean={mean_d:.0f} std={statistics.stdev(distances):.0f} CV={cv:.2f} → threshold_ratio={ratio:.2f}")
    return ratio
def cluster_samples(sequences: list[bytes],threshold_ratio: Optional[float] = None,pair_sample: int = PAIR_SAMPLE, logger: Optional[logging.Logger] = None) -> list[list[int]]:
    """
    Clusters sequences by pairwise edit distance on the first pair_sample bytes
    uses Union-Find: two samples are merged if their distance <= threshold_ratio * max_dist

    ensures that heterogeneous families produce multiple targeted signatures rather than one overly generic signature
    """
    
    n = len(sequences)
    dist_matrix: Dict[Tuple[int, int], int] = {}

    for i in range(n):
        for j in range(i + 1, n):
            d = edlib.align(
                sequences[i][:pair_sample],
                sequences[j][:pair_sample],
                mode="NW", task="distance",
            )["editDistance"]
            dist_matrix[(i, j)] = d
            dist_matrix[(j, i)] = d

    max_dist = max(dist_matrix.values()) if dist_matrix else 0

    #adaptive threshold if not overridden
    if threshold_ratio is None:
        all_dists = [dist_matrix[(i, j)] for i in range(n) for j in range(i + 1, n)]
        threshold_ratio = adaptive_threshold(all_dists, logger)

    threshold = max_dist * threshold_ratio
    if logger:
        logger.info(f"Clustering: dist_max={max_dist} threshold={threshold:.0f} ({threshold_ratio*100:.0f}% of max)")

    # Union-Find
    parent = list(range(n))
    
    
    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        parent[find(x)] = find(y)

    for i in range(n):
        for j in range(i + 1, n):
            if dist_matrix[(i, j)] <= threshold:
                union(i, j)

    clusters: Dict[int, list[int]] = {}
    for i in range(n):
        clusters.setdefault(find(i), []).append(i)

    result = list(clusters.values())
    if logger:
        logger.info(f"Clustering: {len(result)} cluster(s) - {result}")
    return result

    




def align_and_build_yara_strings(a: bytes,b: bytes,max_block_bytes: int = MAX_BLOCK_BYTES,) -> list[str]:
    """
    Formats raw bytes into a YARA hex string with bounded gaps
    
    """


    if len(a) > len(b):
        a, b = b, a

    result = edlib.align(a, b, mode="NW", task="path")
    cigar = result["cigar"]
    if cigar is None:
        return []

    # Parse CIGAR into (op, count) pairs
    ops: list[Tuple[str, int]] = []
    run = 0
    for ch in cigar:
        if ch.isdigit():
            run = run * 10 + (ord(ch) - 48)
        else:
            if run == 0:
                run = 1
            ops.append((ch, run))
            run = 0


    strings: list[str] = []
    current_hex: list[str] = []
    current_len = 0
    in_gap = False
    gap_min = 0
    gap_max = 0
    i = 0

    def flush_gap() -> None:
        nonlocal in_gap, gap_min, gap_max
        if in_gap:
            current_hex.append(f"[{gap_min}-{gap_max}]")
            in_gap = False
            gap_min = 0
            gap_max = 0

    def flush_block() -> None:
        nonlocal current_hex, current_len, in_gap, gap_min, gap_max
        # Discard any trailing gap (gap at end of string is invalid YARA)
        if in_gap:
            in_gap = False
            gap_min = 0
            gap_max = 0
        if current_len >= MIN_BLOCK_SIZE:
            tokens = current_hex[:]
            # Remove leading gaps (gap at start of string is invalid YARA)
            while tokens and tokens[0].startswith('['):
                tokens.pop(0)
            while tokens and tokens[-1].startswith('['):
                tokens.pop()
            byte_count = sum(1 for t in tokens if not t.startswith('['))
            if byte_count >= MIN_BLOCK_SIZE:
                strings.append("{ " + " ".join(tokens) + " }")
        current_hex.clear()
        current_len = 0

    for op, count in ops:
        if i >= len(a):
            break

        if op == '=':
            flush_gap()
            safe = min(count, len(a) - i)
            remaining = safe
            pos = i
            # Forced split every max_block_bytes bytes
            while remaining > 0:
                space = max_block_bytes - current_len
                chunk = min(remaining, space)
                for k in range(chunk):
                    current_hex.append(f"{a[pos+k]:02x}")
                current_len += chunk
                pos += chunk
                remaining -= chunk
                if current_len >= max_block_bytes:
                    flush_block()
            i += safe

        elif op == 'X':
            safe = min(count, len(a) - i)
            if safe > MAX_GAP_SIZE:
                flush_block()
            else:
                if not in_gap:
                    in_gap = True
                    gap_min = safe
                    gap_max = safe
                else:
                    gap_min += safe  # X mandatory in both, so raises lower bound
                    gap_max += safe
            i += safe

        elif op == 'D':
            safe = min(count, len(a) - i)
            if safe > MAX_GAP_SIZE:
                flush_block()
            else:
                if not in_gap:
                    in_gap = True
                    gap_min = 0     #D optional , so lower bound stays 0
                    gap_max = safe
                else:
                    gap_max += safe
            i += safe

        elif op == 'I':
            if count > MAX_GAP_SIZE:
                flush_block()
            else:
                if not in_gap:
                    in_gap = True
                    gap_min = 0     #I optional too, so lower bound stays 0
                    gap_max = count
                else:
                    gap_max += count
            #i not incremented for insertions (they exist only in b)

    flush_block()
    return strings


def local_align_and_build_yara_strings(a: bytes,b: bytes,window_size: int = LOCAL_WINDOW_SIZE,window_step: int = LOCAL_WINDOW_STEP,min_match_ratio: float = LOCAL_MIN_MATCH_RATIO,) -> list[str]:
    """
    to find locally similar regions between two byte sequences using a sliding window approach with edlib HW mode
    For each window of a, edlib HW finds where it best matches within b.
    Windows with enough matching bytes are converted to YARA strings via align_and_build_yara_strings()
    - HW mode: edlib HW aligns pattern a_window against text b allowing free gaps at the start/end of b, so:  equivalent to local alignment for the pattern
    """
    strings: list[str] = []
    seen_offsets: set[int] = set()  # avoid duplicates from overlapping windows

    for start in range(0, len(a) - window_size + 1, window_step):
        window = a[start:start + window_size]

        try:
            res = edlib.align(window, b, mode="HW", task="path")
        except Exception:
            continue

        if res["editDistance"] < 0:
            continue

        # Estimate match ratio: 1-(edit_distance/window_size)
        match_ratio = 1.0 - res["editDistance"] / window_size
        if match_ratio < min_match_ratio:
            continue

        # Find where the best match lands in b
        locs = res.get("locations")
        if not locs:
            continue
        b_start, b_end = locs[0]

        # Avoid generating strings from overlapping windows at same b location
        if b_start in seen_offsets:
            continue
        seen_offsets.add(b_start)

        # Extract the matched region from b and build YARA strings
        b_region = b[b_start:b_end + 1]
        new_strings = align_and_build_yara_strings(window, b_region)
        strings.extend(new_strings)

        if len(strings) >= MAX_STRINGS_PER_CLUSTER:
            break

    return strings



def filter_yara_strings(
    strings: list[str],
    max_null_ratio: float = 0.3,
) -> list[str]:
    """
    Discards YARA strings where more than max_null_ratio of concrete bytes are 0x00
    Such strings match too broadly (data sections, padding) and slow down YARA matching
    Also discards strings with too few unique bytes (repetitive → generic)
    Also discards sequential lookup tables (e.g. ASCII tables present in all PE files)
    """
    filtered = []
    for s in strings:
        tokens = s.strip('{ }').split()
        bytes_only = [t for t in tokens if not t.startswith('[')]
        if not bytes_only:
            continue
        null_ratio = sum(1 for t in bytes_only if t == '00') / len(bytes_only)
        if null_ratio > max_null_ratio:
            continue
        unique_ratio = len(set(bytes_only)) / len(bytes_only)
        if unique_ratio < 0.25:
            continue
        # Filtrer les tables de caractères (lookup tables présentes dans tous les PE)
        byte_vals = [int(t, 16) for t in bytes_only]
        diffs = [byte_vals[i+1] - byte_vals[i] for i in range(len(byte_vals)-1)]
        if len(diffs) > 20 and sum(1 for d in diffs if d == 1) / len(diffs) > 0.85:
            continue
        filtered.append(s)
    return filtered



def sanitize_rule_name(name: str) -> str:
    """Ensures family names conform to YARA rule naming conventions."""
    out = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in name)
    if not out: 
        out = "family"
    if out[0].isdigit(): 
        out = "fam_" + out
    return out



def build_yara_rule_text(family: str, yara_strings: list[str], time_to_build: float) -> str:
    """Constructs YARA rule string corresponding to the malware family signature."""
    
    
    reported_time_to_build = f"{round(time_to_build, 2)} sec" if time_to_build < 60.0 else f"{round(time_to_build/60.0, 2)} min"

    rule_name = sanitize_rule_name(family)
    strings_block = "\n".join(f"     $s{idx} = {s}" for idx, s in enumerate(yara_strings, 1))

    return f"""rule {rule_name}
    {{
        meta:
            family = "{family}"
            nb_strings = {len(yara_strings)}
            time_to_build = "{reported_time_to_build}"
        strings:
            {strings_block}
        condition:
            any of them
    }}"""






def k_lcs_clustered(sequences: list[bytes],*,logger: logging.Logger,workers: int = 0,use_local: bool = False) -> list[str]:
    """
    Generates YARA strings for a family by clustering samples first, then aligning the median pair within each cluster
    handles heterogeneous families better by producing targeted signatures per sub-group
    returns a flat list of YARA hex strings (one per valid cluster block)
    """

    if len(sequences) < 2:
        return []

    clusters = cluster_samples(sequences,threshold_ratio=None,logger=logger)

    all_strings: list[str] = []
    for cidx, cluster in enumerate(clusters):
        if len(cluster) < 2:
            logger.info(f"Cluster {cidx}: singleton — skipped")
            continue

        # Find the median pair within the cluster (fast: uses PAIR_SAMPLE bytes)
        pairs: list[Tuple[int, int, int]] = []
        for ii in range(len(cluster)):
            for jj in range(ii + 1, len(cluster)):
                si, sj = cluster[ii], cluster[jj]
                d = edlib.align(
                    sequences[si][:PAIR_SAMPLE],
                    sequences[sj][:PAIR_SAMPLE],
                    mode="NW", task="distance",
                )["editDistance"]
                pairs.append((d, si, sj))
        pairs.sort()
        med = statistics.median(d for d, _, _ in pairs)
        best = min(pairs, key=lambda x: abs(x[0] - med))
        i_med, j_med = best[1], best[2]

        t0 = monotonic()

        #choose alignment strategy
        if use_local:
            strings = local_align_and_build_yara_strings(sequences[i_med], sequences[j_med])
            logger.info(f"Cluster {cidx}: local alignment used")
        else:
            strings = align_and_build_yara_strings(sequences[i_med], sequences[j_med])

        elapsed = monotonic() - t0


        if elapsed > 15:
            logger.warning(f"Cluster {cidx}: alignment too slow ({elapsed:.0f}s) — skipped")
            continue

        strings = filter_yara_strings(strings)
        strings = strings[:MAX_STRINGS_PER_CLUSTER]
        logger.info(
            f"Cluster {cidx} ({len(cluster)} samples, pair {i_med},{j_med}): "
            f"{len(strings)} strings in {elapsed:.1f}s"
        )
        all_strings.extend(strings)

    return all_strings





#batch run for kaggle:

def run_pipeline_on_family(family_name: str,zip_path: str,password: bytes,truncate: int,samples_goodware: list[bytes],logger: logging.Logger,) -> dict:

    import yara as yara_lib
    result = {
        "family": family_name,
        "nb_samples": 0,
        "nb_strings": 0,
        "nb_clusters": 0,
        "recall": 0.0,
        "precision": 0.0,
        "f1": 0.0,
        "truncate_used": truncate,
        "alignment_mode": "global",
        "status": "ok",
    }

    attempts = [(truncate, False)] + [(t, False) for t in TRUNCATE_RETRY_SIZES] + [(truncate, True)]

    sequences = None
    yara_strings = None

    for attempt_truncate, use_local in attempts:
        try:
            sequences = collect_samples_from_zip(zip_path, family_name, password,attempt_truncate)
            if len(sequences) < 2:
                result["status"] = "not_enough_samples"
                return result
            result["nb_samples"] = len(sequences)

            t0 = monotonic()
            yara_strings = k_lcs_clustered(sequences, logger=logger, use_local=use_local)
            result["nb_clusters"] = len(cluster_samples(sequences,threshold_ratio=None,logger=None))

            if yara_strings:
                result["truncate_used"] = attempt_truncate
                result["alignment_mode"] = "local" if use_local else "global"
                if attempt_truncate != truncate:
                    logger.info(f"Improvement 7: succeeded with truncate={attempt_truncate}")
                if use_local:
                    logger.info(f"Improvement 8: succeeded with local alignment")
                break
            else:
                logger.info(
                    f"no_strings with truncate={attempt_truncate} local={use_local} — retrying..."
                )

        except Exception as e:
            result["status"] = f"error: {e}"
            logger.error(str(e))
            return result

    if not yara_strings:
        result["status"] = "no_strings"
        return result
    result["nb_strings"] = len(yara_strings)

    try:
        rule = yara_lib.compile(
        source=build_yara_rule_text(family_name, yara_strings, monotonic() - t0)
        )
        

        tp, fn = 0, 0
        for sample in sequences:
            try:
                if rule.match(data=sample, timeout=2):
                    tp += 1
                else:
                    fn += 1
            except yara_lib.TimeoutError:
                fn += 1

        fp = 0
        for sample in samples_goodware:
            try:
                if rule.match(data=sample, timeout=2):
                    fp += 1
            except yara_lib.TimeoutError:
                pass

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        result.update({
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "f1": round(f1, 3),
        })
        logger.info(f"TP={tp} FP={fp} FN={fn} → F1={f1:.0%}")

        del sequences, rule
        gc.collect()

    except Exception as e:
        result["status"] = f"error: {e}"
        logger.error(str(e))

    return result







def main():
    ap = argparse.ArgumentParser(description="Malware family YARA signature generator, from k representative samples, based on the LCS (Longest Common Subsequence) algorithm")
    ap.add_argument("family_dirpath", type=str, help="Directory containing the family's representative binaries to build the signature from.")
    ap.add_argument("--truncate-bytes", type=int, default=TRUNCATE_BYTES_DEFAULT, help=f"Read up to N bytes per file (default: {TRUNCATE_BYTES_DEFAULT})")
    ap.add_argument("--cluster-threshold",type=float,default=None,help=f"Union-Find threshold as fraction of max distance (default: {CLUSTER_THRESHOLD})")
    ap.add_argument("--local",action="store_true",default=False,help="Use local alignment (sliding window HW mode) instead of global NW")
    ap.add_argument("-v", "--verbose", action="count", default=0, help="-v: INFO, -vv: DEBUG")
    ap.add_argument("--workers", type=int, default=0, help="Number of processes to parallelize distance computation (default: 0)")
    args = ap.parse_args()

    level = logging.WARNING if args.verbose == 0 else (logging.INFO if args.verbose == 1 else logging.DEBUG)
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)-5s | %(message)s")
    logger = logging.getLogger("LCS")

    family_dirpath = args.family_dirpath
    if not os.path.isdir(family_dirpath):
        raise SystemExit(f"Not a directory: {family_dirpath}")
        
    family = os.path.basename(os.path.normpath(family_dirpath))
    logger.info(f"Family: {family}")
    logger.info(f"Input directory: {os.path.abspath(family_dirpath)}")
    logger.info(f"Truncation limit: {args.truncate_bytes} bytes")
    logger.info(f"Cluster threshold: {'adaptive' if args.cluster_threshold is None else args.cluster_threshold}")
    logger.info(f"Alignment mode: {'local' if args.local else 'global'}")

    start_time = monotonic()
    sequences = collect_samples(family_dirpath, args.truncate_bytes, logger)
    yara_strings = k_lcs_clustered(sequences, logger=logger, workers=args.workers,use_local=args.local)
    time_to_build = monotonic() - start_time
    
    logger.info(f"generated {len(yara_strings)} YARA strings in {time_to_build:.2f}s")
    if not yara_strings:
        logger.error("No YARA strings generated- no common subsequence found. Not writing a YARA rule")
        raise SystemExit(1)

    rule_text = build_yara_rule_text(family, yara_strings, time_to_build)
    family_signatures_dirpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures", family)
    os.makedirs(family_signatures_dirpath, exist_ok=True)
    output_filepath = os.path.join(family_signatures_dirpath, f"{family}.yar")
    with open(output_filepath, 'w') as file:
        file.write(rule_text)
    print(f"Wrote signature to {output_filepath}")

if __name__ == "__main__":
    main()
