"""
Fast LCS to YARA Signature Generator.
Uses edlib for C-backed Levenshtein distance and global alignment pathing.
Implements a greedy pairwise reduction with multiprocessing and VxSig-style gap formatting.

Improvements over André's baseline:
  1. Clustering (Union-Find) before LCS to handle heterogeneous families
  2. Median-based pair selection instead of closest-first (more robust to outliers)
  3. Bounded gaps [min-max] instead of [-] (fast YARA matching)
  4. Multi-string rules with 'any of them' (one string per cluster)
  5. --batch-size argument to vary train set size (train != test)
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
MAX_GAP          = 20   # gap borné : si gap_max > MAX_GAP, on coupe la string
MIN_BLOCK        = 8    # taille minimale d'un bloc pour être gardé (bytes)
MAX_BLOCK_BYTES  = 200  # taille max d'un bloc en bytes avant coupure forcée
MAX_STRINGS      = 20   # nombre max de strings YARA par règle

CLUSTER_SAMPLE_BYTES = 10_000  # bytes utilisés pour le clustering (rapide)
CLUSTER_THRESHOLD    = 0.3     # seuil : dist_normalisée < 0.30 → même cluster


# ─────────────────────────────────────────────
# I/O
# ─────────────────────────────────────────────

def read_truncated(sample_filepath: str, limit: int) -> bytes:
    """Reads a file up to a specified byte limit."""
    with open(sample_filepath, 'rb') as file:
        return file.read(limit)


def worker_init():
    """Instructs child processes to ignore SIGINT (Ctrl+C)."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)


# ─────────────────────────────────────────────
# CLUSTERING  (Union-Find on pairwise distances)
# ─────────────────────────────────────────────

def _cluster_dist_task(args: Tuple[int, int, bytes, bytes]) -> Tuple[int, int, float]:
    """Worker multiprocessing : distance normalisée sur court préfixe."""
    i, j, a, b = args
    d = edlib.align(a, b, mode="NW", task="distance")["editDistance"]
    norm = d / max(len(a), len(b)) if max(len(a), len(b)) > 0 else 0.0
    return (i, j, norm)


def cluster_samples(sequences: list[bytes], threshold: float,
                    logger: logging.Logger, pool=None) -> list[list[int]]:
    """
    Regroupe les séquences en clusters via Union-Find.
    Deux séquences sont liées si leur distance normalisée
    (calculée sur un court préfixe) est inférieure à threshold.

    Retourne une liste de clusters, chaque cluster étant une liste d'indices.

    Pourquoi Union-Find ?
      Vérification pairwise O(N^2) simple et efficace.
      Gère naturellement la transitivité :
      si A~B et B~C alors A,B,C sont dans le même cluster.
    """
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


# ─────────────────────────────────────────────
# PAIRWISE DISTANCES
# ─────────────────────────────────────────────

def _compute_edit_distance_task(args: Tuple[int, int, bytes, bytes]) -> Tuple[int, int, int]:
    """Multiprocessing worker function for Levenshtein distance calculation."""
    i, j, a_bytes, b_bytes = args
    dist = edlib.align(a_bytes, b_bytes, mode="NW", task="distance")["editDistance"]
    return (dist, i, j)


def build_all_distances(items: Dict[int, bytes], active_ids: list,
                        pool=None) -> Dict[Tuple[int, int], int]:
    """
    Calcule toutes les distances pairwise entre les séquences actives.
    Retourne un dict (i,j) -> distance  (avec i < j toujours).
    """
    tasks = [(i, j, items[i], items[j])
             for ix, i in enumerate(active_ids)
             for j in active_ids[ix+1:]]

    if pool and tasks:
        raw = list(pool.imap(_compute_edit_distance_task, tasks, chunksize=1))
    else:
        raw = [_compute_edit_distance_task(t) for t in tasks]

    return {(min(i, j), max(i, j)): d for d, i, j in raw}


def build_distance_heap(items: Dict[int, bytes], active_ids: set,
                        pool=None) -> list[Tuple[int, int, int]]:
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


# ─────────────────────────────────────────────
# PAIR LCS
# ─────────────────────────────────────────────

def pair_lcs(a: bytes, b: bytes) -> bytes:
    """
    Computes a common subsequence using edlib NW alignment.
    Only keeps '=' (exact match) runs from the CIGAR string.
    """
    res = edlib.align(a, b, mode="NW", task="path")
    cigar = res["cigar"]
    if cigar is None:
        return b""

    i = j = run = 0
    output = bytearray()

    for ch in cigar:
        if ch.isdigit():
            run = run * 10 + (ord(ch) - 48)
            continue
        if run == 0:
            run = 1
        if ch == "=":
            output.extend(a[i:i+run]); i += run; j += run
        elif ch in ("X", "M"):
            i += run; j += run
        elif ch == "I":
            j += run
        elif ch == "D":
            i += run
        run = 0

    return bytes(output)


# ─────────────────────────────────────────────
# BASELINE k-LCS  (closest-first, André's method)
# ─────────────────────────────────────────────

def k_lcs(sequences: list[bytes], *, logger: logging.Logger, workers: int) -> bytes:
    """
    Reduces k sequences to one common subsequence.
    Greedy min-heap: always merges the closest pair first.
    Kept for comparison with the median-based method.
    """
    if not sequences:
        return b""

    items: Dict[int, bytes] = {id: seq for id, seq in enumerate(sequences)}
    active = set(items.keys())

    pool = None
    if workers:
        pool = Pool(processes=workers, initializer=worker_init)

    step = 1
    try:
        while len(active) > 1:
            heap = build_distance_heap(items, active, pool)
            dist, i, j = heapq.heappop(heap)
            logger.info(f"[step {step}] closest pair: ({i},{j}) |A|={len(items[i])} |B|={len(items[j])} d={dist}")

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


# ─────────────────────────────────────────────
# MEDIAN k-LCS  (our improvement)
# ─────────────────────────────────────────────

def k_lcs_median(sequences: list[bytes], *,
                 logger: logging.Logger, pool=None) -> bytes:
    """
    Réduit k séquences en une LCS commune avec sélection par MÉDIANE.

    Pourquoi médiane plutôt que plus-proches-en-premier ?
    ──────────────────────────────────────────────────────
    La méthode baseline (André) merge toujours la paire la plus proche.
    Problème : un outlier très différent de tous les autres sera mergé
    en dernier, et effondrera la LCS accumulée à ce step final.

    Avec la médiane : à chaque step on calcule pour chaque séquence i
    sa distance MÉDIANE à toutes les autres. On choisit i* = celle avec
    la médiane la plus basse (la plus centrale). On la merge ensuite
    avec sa plus proche voisine j*.

    Les outliers ont une médiane élevée → ils sont mergés en dernier,
    quand la LCS commune est déjà bien établie → moins de dégâts.
    """
    if not sequences:
        return b""
    if len(sequences) == 1:
        return sequences[0]

    items: Dict[int, bytes] = {idx: s for idx, s in enumerate(sequences)}
    active = list(items.keys())

    step = 1
    try:
        while len(active) > 1:
            dist_map = build_all_distances(items, active, pool)

            median_scores: Dict[int, float] = {}
            for i in active:
                dists_i = [dist_map[(min(i, j), max(i, j))]
                           for j in active if j != i]
                median_scores[i] = statistics.median(dists_i) if dists_i else 0.0

            i_star = min(active, key=lambda i: median_scores[i])
            j_star = min(
                (j for j in active if j != i_star),
                key=lambda j: dist_map[(min(i_star, j), max(i_star, j))]
            )

            d_star = dist_map[(min(i_star, j_star), max(i_star, j_star))]
            logger.info(
                f"[step {step}] central: {i_star} "
                f"(median_dist={median_scores[i_star]:.0f}), "
                f"merge avec {j_star} d={d_star} "
                f"|A|={len(items[i_star])} |B|={len(items[j_star])}"
            )

            t0 = monotonic()
            lcs_ij = pair_lcs(items[i_star], items[j_star])
            logger.info(f"[step {step}] LCS → {len(lcs_ij)} bytes en {monotonic()-t0:.2f}s")

            items[i_star] = lcs_ij
            active.remove(j_star)
            del items[j_star]

            if lcs_ij:
                allowed = set(lcs_ij)
                for k in active:
                    if k != i_star:
                        items[k] = bytes(b for b in items[k] if b in allowed)

            step += 1

    except KeyboardInterrupt:
        raise

    return items[active[0]]


# ─────────────────────────────────────────────
# YARA FORMATTING  (bounded gaps + forced cuts)
# ─────────────────────────────────────────────

def yara_format_lcs(lcs: bytes, sequences: list[bytes], *,
                    bytes_per_line: int = 24,
                    max_gap: int = MAX_GAP,
                    min_block: int = MIN_BLOCK,
                    max_block_bytes: int = MAX_BLOCK_BYTES) -> list[str]:
    """
    Convertit la LCS en strings YARA avec gaps BORNÉS [min-max].

    Deux critères de coupure :
      1. gap_max > max_gap       → le gap est trop grand, on coupe
      2. bloc atteint max_block_bytes → coupure forcée pour éviter
         les strings trop longues que YARA ne peut pas matcher efficacement

    Blocs < min_block bytes sont supprimés.
    Retourne une liste de strings hex YARA.
    """

    def lcs_positions(seq: bytes, lcs: bytes) -> list[int] | None:
        buckets = [[] for _ in range(256)]
        for idx, b in enumerate(seq):
            buckets[b].append(idx)
        pos, curr = [], -1
        for b in lcs:
            bp = buckets[b]
            k  = bisect_right(bp, curr)
            if k == len(bp):
                return None
            curr = bp[k]
            pos.append(curr)
        return pos

    def flush(block: list[str]) -> str | None:
        hex_tokens = [t for t in block if not t.startswith("[")]
        nbytes = len(hex_tokens)
        if nbytes < min_block:
            return None
        # Filtrer les blocs avec trop de bytes nuls (00) — trop génériques
        null_count = sum(1 for t in hex_tokens if t == "00")
        if null_count / nbytes > 0.6:  # plus de 40% de 00 → on ignore
            return None
        lines, line, count = [], [], 0
        for t in block:
            line.append(t)
            count += 1
            if count >= bytes_per_line and t is not block[-1]:
                lines.append(" ".join(line))
                line, count = [], 0
        if line:
            lines.append(" ".join(line))
        s = " \n        ".join(lines)
        return ("{ " + s + " }") if len(lines) > 1 else ("{ " + lines[0] + " }")
    
    if not lcs:
        return []

    positions = [p for s in sequences if (p := lcs_positions(s, lcs)) is not None]
    if not positions:
        return []

    yara_strings, block = [], [f"{lcs[0]:02x}"]

    for i in range(len(lcs) - 1):
        contiguous = all(p[i+1] == p[i] + 1 for p in positions)

        if contiguous:
            block.append(f"{lcs[i+1]:02x}")
        else:
            # Toujours couper sur un gap — pas de [min-max]
            r = flush(block)
            if r:
                yara_strings.append(r)
            block = [f"{lcs[i+1]:02x}"]

        # Coupure forcée si le bloc est trop long
        byte_count = sum(1 for t in block if not t.startswith("["))
        if byte_count >= max_block_bytes:
            r = flush(block)
            if r:
                yara_strings.append(r)
            last_hex = next((t for t in reversed(block) if not t.startswith("[")), None)
            block = [last_hex] if last_hex else []

    if block:
        r = flush(block)
        if r:
            yara_strings.append(r)

    return yara_strings


# ─────────────────────────────────────────────
# FULL PIPELINE
# ─────────────────────────────────────────────

def run_pipeline(sequences: list[bytes], family: str,
                 time_to_build: float, logger: logging.Logger,
                 pool=None) -> str:
    """
    Pipeline complet :
      1. Clustering des séquences (Union-Find sur courts préfixes)
      2. k_lcs_median sur chaque cluster indépendamment
      3. Formatage en strings YARA bornées avec coupure forcée
      4. Règle unique avec 'any of them'

    Pourquoi une LCS par cluster ?
      Une LCS globale force TOUS les fichiers à partager les mêmes bytes.
      Pour les familles hétérogènes, cela produit une LCS quasi-vide.
      Le clustering permet à chaque sous-groupe homogène de produire
      une bonne LCS, et 'any of them' détecte n'importe quelle variante.
    """
    clusters = cluster_samples(sequences, CLUSTER_THRESHOLD, logger, pool)

    all_strings: list[str] = []
    for k, cluster_indices in enumerate(clusters):
        cluster_seqs = [sequences[i] for i in cluster_indices]
        logger.info(f"Cluster {k}: LCS sur {len(cluster_seqs)} séquences")

        if len(cluster_seqs) == 1:
            # Séquence unique : on prend les 64 premiers bytes comme ancre
            lcs = cluster_seqs[0][:64]
            logger.info(f"Cluster {k}: séquence unique, ancre de {len(lcs)} bytes")
        else:
            lcs = k_lcs_median(cluster_seqs, logger=logger, pool=pool)
            logger.info(f"Cluster {k}: LCS = {len(lcs)} bytes")

        strings = yara_format_lcs(lcs, cluster_seqs,
                                  max_gap=MAX_GAP,
                                  min_block=MIN_BLOCK,
                                  max_block_bytes=MAX_BLOCK_BYTES)
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
        max_block_bytes = {MAX_BLOCK_BYTES}
        cluster_threshold = "{CLUSTER_THRESHOLD}"
        pair_selection = "median"
        time_to_build = "{reported}"
    strings:
{strings_block}
    condition:
        {condition}
}}"""


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    global MAX_GAP, MIN_BLOCK, MAX_STRINGS, MAX_BLOCK_BYTES

    ap = argparse.ArgumentParser(
        description="LCS YARA generator — clustering + médiane + gaps bornés"
    )
    ap.add_argument("family_dirpath", type=str,
                    help="Dossier contenant les binaires d'entraînement")
    ap.add_argument("--truncate-bytes",  type=int, default=TRUNCATE_BYTES_DEFAULT)
    ap.add_argument("--batch-size",      type=int, default=10,
                    help="Nombre de fichiers d'entraînement (défaut: 10). "
                         "Varier pour tester l'effet train!=test : 10, 20, 30, 40, 50")
    ap.add_argument("--max-gap",         type=int, default=MAX_GAP)
    ap.add_argument("--min-block",       type=int, default=MIN_BLOCK)
    ap.add_argument("--max-block-bytes", type=int, default=MAX_BLOCK_BYTES)
    ap.add_argument("--max-strings",     type=int, default=MAX_STRINGS)
    ap.add_argument("--workers",         type=int, default=0)
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args()

    MAX_GAP         = args.max_gap
    MIN_BLOCK       = args.min_block
    MAX_BLOCK_BYTES = args.max_block_bytes
    MAX_STRINGS     = args.max_strings

    level = (logging.WARNING if args.verbose == 0
             else logging.INFO if args.verbose == 1
             else logging.DEBUG)
    logging.basicConfig(level=level,
                        format="%(asctime)s | %(levelname)-5s | %(message)s")
    logger = logging.getLogger("LCS")

    if not os.path.isdir(args.family_dirpath):
        raise SystemExit(f"Not a directory: {args.family_dirpath}")

    family = os.path.basename(os.path.normpath(args.family_dirpath))
    logger.info(f"Family: {family} | batch_size={args.batch_size} | "
                f"max_gap={MAX_GAP} | min_block={MIN_BLOCK} | "
                f"max_block_bytes={MAX_BLOCK_BYTES}")

    pool = None
    if args.workers:
        pool = Pool(processes=args.workers, initializer=worker_init)

    try:
        t0 = monotonic()

        all_files = sorted(os.listdir(args.family_dirpath))
        selected  = all_files[:args.batch_size]
        logger.info(f"Utilisation de {len(selected)}/{len(all_files)} fichiers "
                    f"(batch_size={args.batch_size})")
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
