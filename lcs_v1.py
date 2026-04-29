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

TRUNCATE_BYTES_DEFAULT = 1000000 

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
    log_interval = max(1, total // 10)  # log every ~10%
    t_heap_start = monotonic()

    if logger:
        logger.info(f"  Building distance heap: {total} pairs to compute ({n} active sequences)...")

    if pool and tasks:  # multi-processing
        for done, (dist, i, j) in enumerate(pool.imap(_compute_edit_distance_task, tasks, chunksize=4), 1):
            heap.append((dist, i, j))
            if logger and done % log_interval == 0:
                elapsed = monotonic() - t_heap_start
                eta = elapsed / done * (total - done)
                logger.info(f"  [{done}/{total} pairs | {done*100//total}% | elapsed {elapsed:.0f}s | ETA ~{eta:.0f}s]")
    else:  # single-process mode
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






#parameters clustering

cluster_sample_bytes=10000 #take the first 10KB of each sample to compute the distance for clustering
cluster_threshold=0.3 #seuil behind it 2 samples are considered similar to be in same cluster


def cluster_samples(sequences: list[bytes], logger: logging.Logger):
    '''
    regroup the sequences in cluster via union find
    '''
    n=len(sequences)
    short= [s[:cluster_sample_bytes] for s in sequences]#take short prefix for fast distance computation 
    parent=[]
    for i in range(n):
        parent.append(i)

    def find(x):
        while parent[x]!=x:
            parent[x]=parent[parent[x]]
            x=parent[x]
        return x
    
    def union(x,y):
        parent[find(x)]=find(y)


    for i in range(n):
        for j in range(i+1,n):
            #compute distance for pair on short prefix
            result=edlib.align(short[i],short[j], mode="NW", task="distance")
            d=result["editDistance"]
            norm=d/max(len(short[i]),len(short[j]))#normalize distance (between 0 and1)

            if norm<cluster_threshold:
                union(i,j)#if similar (behind threshold), same cluster
    
    #regroup samples by cluster
    clusters={}
    for i in range(n):
        s=find(i)
        if s not in clusters:
            clusters[s]=[]
        clusters[s].append(i)
    
    result=list(clusters.values())
    logger.info(f"Clustering results:{len(result)} clusters formed")
    return result





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

    total_steps = len(sequences) - 1
    pool = None
    if workers:
        pool = Pool(processes=workers, initializer=worker_init)

    step = 1
    try:
        # Loop until only one sequence (i.e., the final LCS) is left
        while len(active) > 1:
            logger.info(f"[step {step}/{total_steps}] {len(active)} sequences remaining — rebuilding distance heap...")
            # (Re)Build a fresh min-heap containing only valid active distances
            heap = build_distance_heap(items, active, pool, logger=logger)

            # Get the closest pair (eventual ties are resolved by picking the smallest IDs)
            dist, i, j = heapq.heappop(heap)

            logger.info(f"[step {step}/{total_steps}] closest pair: ({i},{j}) |A|={len(items[i])} |B|={len(items[j])} d={dist}")

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

            logger.info(f"[step {step}/{total_steps}] done — {len(active)} sequences remaining")
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



def clean_block(tokens: list[str]) -> list[str] | None:    
    '''
    filter for lots a of null bytes, header PE, block too small
    '''
    hex_tokens=[t for t in tokens if not t.startswith("[")]
    #filter too small block
    if len(hex_tokens)<8:
        return None
    
    #filter too many null bytes
    null_count=sum(1 for t in hex_tokens if t == "00")
    if null_count/len(hex_tokens)>0.4:
        return None
    
    #filter PE header
    if len(hex_tokens)>=2 and hex_tokens[0]=="4d" and hex_tokens[1]=="5a": #"MZ"
        #cut tokens
        for idx, t in enumerate(tokens):
            if t == "5a":
                tokens = tokens[idx+1:]
                break
    return tokens






def yara_format_lcs(lcs: bytes, sequences: list[bytes], *, bytes_per_line: int = 24) -> list[str]:
    """
    Formats raw bytes into a YARA hex string.
    Inserts '[-]' wildcards only between non-contiguous sequences.
    """

    def sequence_lcs_bytes_positions(sequence: bytes, lcs: bytes) -> list[int] | None:
        """Returns the leftmost index positions of 'lcs' as a subsequence within 'sequence'."""
        buckets = [[] for _ in range(256)] # an array of 256 empty lists (one for every possible byte value, 0x00 to 0xFF)
        # Reads an original sequence and logs the index position of every single byte into its corresponding bucket
        for idx, b in enumerate(sequence): 
            buckets[b].append(idx)
            
        pos = []
        curr_index = -1

        # Looks at that byte's bucket and uses bisect_right 
        for b in lcs:
            b_positions = buckets[b]
            k = bisect_right(b_positions, curr_index) # binary search function finding the next occurrence of the processed LCS's byte that is greater than the current index
            if k == len(b_positions):
                return None
            curr_index = b_positions[k]
            pos.append(curr_index)
            
        return pos
    
    if not lcs:
        return []
        
    positions: list[list[int]] = [] # Positions of LCS bytes in each input samples' respective byte sequences
    for sequence in sequences:
        sequence_positions = sequence_lcs_bytes_positions(sequence, lcs)
        if sequence_positions is not None:
            positions.append(sequence_positions)
    
    yara_strings = [] #store all the yara strings
    tokens: list[str] = [f"{lcs[0]:02x}"]
    
    for i in range(len(lcs) - 1):
        contiguous_in_all = all(p[i+1] == p[i] + 1 for p in positions) # checks whether the given pair of LCS bytes is present in all sequences in a contiguous manner
        
        if not contiguous_in_all:
            #compute the gap size across all samples
            gaps = [p[i+1] - p[i] for p in positions]
            gap_min=min(gaps)
            gap_max=max(gaps)
            if gap_max>50:
                #gap too large, so cut and start new yara string to avoid too many wildcards
                cleaned = clean_block(tokens)
                if cleaned is not None:
                    yara_strings.append(cleaned)
                tokens=[f"{lcs[i+1]:02x}"]#start new block with the next byte of the lcs
            else:
                #we insert [min-max]
                tokens.append("["+str(gap_min)+"-"+str(gap_max)+"]")
                tokens.append(f"{lcs[i+1]:02x}")

        else:
            #no gap
            tokens.append(f"{lcs[i+1]:02x}")
    
    
    cleaned = clean_block(tokens)
    if cleaned is not None:
        yara_strings.append(cleaned)

    #convert each list of tockens to yara hex string format
    return ["{ " + " ".join(t) + " }" for t in yara_strings]




def build_yara_rule_text(family: str,yara_strings: list[str], time_to_build: float) -> str:
    """Constructs YARA rule string corresponding to the malware family signature."""
    
    #one $si per yara string from yara_format_lcs
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
    ap = argparse.ArgumentParser(description="Malware family YARA signature generator, from k representative samples, based on the LCS (Longest Common Subsequence) algorithm")
    ap.add_argument("family_dirpath", type=str, help="Directory containing the family's representative binaries to build the signature from.")
    ap.add_argument("--truncate-bytes", type=int, default=TRUNCATE_BYTES_DEFAULT, help=f"Read up to N bytes per file (default: {TRUNCATE_BYTES_DEFAULT})")
    ap.add_argument("-v", "--verbose", action="count", default=0, help="-v: INFO, -vv: DEBUG")
    ap.add_argument("--workers", type=int, default=0, help="Number of processes to parallelize distance computation (default: 0)")
    ap.add_argument("--batch-size", type=int, default=None, help="Number of files to use for training (default: all)")
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

    try:
        start_time = monotonic()
        sequences = collect_samples(family_dirpath, args.truncate_bytes, logger)
        
        if args.batch_size:
            sequences = sequences[:args.batch_size]
            logger.info(f"Using first {len(sequences)} files (batch-size={args.batch_size})")

        clusters = cluster_samples(sequences, logger)
        
        all_yara_strings = []
        for cluster in clusters:
            cluster_sequences=[sequences[i] for i in cluster]
            lcs = k_lcs(cluster_sequences, logger=logger, workers=args.workers)
            yara_strings = yara_format_lcs(lcs, cluster_sequences)
            all_yara_strings.extend(yara_strings)

        time_to_build = monotonic() - start_time
        rule_text = build_yara_rule_text(family, all_yara_strings, time_to_build)

        family_signatures_dirpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures", family)
        os.makedirs(family_signatures_dirpath, exist_ok=True)
        output_filepath = os.path.join(family_signatures_dirpath, f"{family}.yar")
        with open(output_filepath, 'w') as file:
            file.write(rule_text)
        print(f"Wrote signature to {output_filepath}")
    except KeyboardInterrupt:
        logger.error("Execution interrupted by user (Ctrl+C). Shutting down...")
        sys.exit(1)

if __name__ == "__main__":
    main()
