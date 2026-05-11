"""
param_sweep.py v2 — Automatisation sweep paramètres lcs_v1.py
Correction: les paramètres sont passés explicitement aux fonctions
(les default args Python sont liés à la définition, pas à l'exécution).

Usage:
    python param_sweep.py --param max_gap_size --values 10 20 30 50 75 100
    python param_sweep.py --param cluster_threshold --values 0.3 0.5 0.7 0.8 0.9
    python param_sweep.py --param local_min_match_ratio --values 0.2 0.3 0.4 0.5 0.6
    python param_sweep.py --param local_window_size --values 256 512 1024 2048
"""

import argparse
import sys
import os
import yara
import csv
import time
import edlib
import statistics
import logging
import importlib

# ── Config ────────────────────────────────────────────────────────────────────
SWEEP_FAMILIES   = ['neshta', 'salgorea', 'blackie']
DATASET_ROOT     = 'reduced_dataset'
SIGNATURES_DIR   = 'sweep_results'

# Valeurs de référence — tous les autres paramètres restent à ces valeurs
REFERENCE = {
    'max_gap_size':           50,
    'min_block_size':         16,
    'max_block_bytes':        500,
    'max_strings_per_cluster':20,
    'cluster_threshold':      0.8,
    'cluster_sample_bytes':   10000,
    'local_window_size':      1024,
    'local_window_step':      512,
    'local_min_match_ratio':  0.4,
}

INT_PARAMS = {'max_gap_size','min_block_size','max_block_bytes',
              'max_strings_per_cluster','cluster_sample_bytes',
              'local_window_size','local_window_step'}

def get_lcs_module():
    if 'lcs_v1' in sys.modules:
        del sys.modules['lcs_v1']
    cwd = os.path.dirname(os.path.abspath(__file__))
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    return importlib.import_module('lcs_v1')


def _align_and_build(a: bytes, b: bytes,
                     max_gap_size: int, min_block_size: int, max_block_bytes: int) -> list:
    """
    Copie locale de align_and_build_yara_strings avec paramètres explicites.
    Nécessaire car les default args Python sont résolus à la définition de la fonction.
    """
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
            current_string.append("[" + str(gap_min) + "-" + str(gap_max) + "]")
            in_gap = False; gap_min = 0; gap_max = 0

    def flush_block():
        nonlocal current_string, current_len, in_gap, gap_min, gap_max
        if in_gap:
            in_gap = False; gap_min = 0; gap_max = 0
        if current_len >= min_block_size:
            tokens = current_string[:]
            while tokens and tokens[0][0] == "[": tokens.pop(0)
            while tokens and tokens[-1][0] == "[": tokens.pop()
            if sum(1 for t in tokens if t[0] != "[") >= min_block_size:
                strings.append("{ " + " ".join(tokens) + " }")
        current_string.clear()
        current_len = 0

    for operation, count in operations:
        if i >= len(a):
            break
        if operation == "=":
            flush_gap()
            safe = min(count, len(a) - i)
            rem = safe; pos = i
            while rem > 0:
                space = max_block_bytes - current_len
                chunk = min(space, rem)
                for k in range(chunk):
                    current_string.append(f"{a[pos+k]:02x}")
                current_len += chunk; pos += chunk; rem -= chunk
                if current_len >= max_block_bytes:
                    flush_block()
            i += safe
        elif operation == "X":
            safe = min(count, len(a) - i)
            if safe > max_gap_size:
                flush_block()
            else:
                if not in_gap: in_gap = True; gap_min = safe; gap_max = safe
                else: gap_min += safe; gap_max += safe
            i += safe
        elif operation == "D":
            safe = min(count, len(a) - i)
            if safe > max_gap_size:
                flush_block()
            else:
                if not in_gap: in_gap = True; gap_min = 0; gap_max = safe
                else: gap_max += safe
            i += safe
        elif operation == "I":
            if count > max_gap_size:
                flush_block()
            else:
                if not in_gap: in_gap = True; gap_min = 0; gap_max = count
                else: gap_max += count
    flush_block()
    return strings


def generate_signature(family: str, out_dir: str, params: dict) -> float:
    """Génère la signature avec tous les paramètres passés explicitement."""
    mod = get_lcs_module()
    logger = logging.getLogger('sweep')
    logger.setLevel(logging.WARNING)

    training_dir = os.path.join(DATASET_ROOT, 'malware', 'training', family)
    if not os.path.isdir(training_dir):
        print(f"  [ERREUR] {training_dir} introuvable")
        return -1

    p_max_gap           = params['max_gap_size']
    p_min_block         = params['min_block_size']
    p_max_block_bytes   = params['max_block_bytes']
    p_max_strings       = params['max_strings_per_cluster']
    p_clust_thresh      = params['cluster_threshold']
    p_clust_bytes       = params['cluster_sample_bytes']
    p_win_size          = params['local_window_size']
    p_win_step          = params['local_window_step']
    p_min_match         = params['local_min_match_ratio']

    t0 = time.monotonic()
    try:
        sequences = mod.collect_samples(training_dir, mod.TRUNCATE_BYTES_DEFAULT, logger)

        # Clustering Union-Find avec cluster_threshold explicite
        n = len(sequences)
        prefix = [s[:p_clust_bytes] for s in sequences]
        parent = list(range(n))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]; x = parent[x]
            return x

        def union(x, y):
            a, b = find(x), find(y)
            if a != b: parent[a] = b

        dists = {}
        for i in range(n):
            for j in range(i+1, n):
                dists[(i,j)] = edlib.align(prefix[i], prefix[j],
                                           mode="NW", task="distance")["editDistance"]

        max_d = max(dists.values()) if dists else 0
        thresh = p_clust_thresh * max_d
        for (i, j), d in dists.items():
            if d <= thresh: union(i, j)

        clusters_dict = {}
        for i in range(n):
            clusters_dict.setdefault(find(i), []).append(i)
        clusters = list(clusters_dict.values())

        all_yara_strings = []

        for cluster in clusters:
            cseqs = [sequences[i] for i in cluster]

            # Paire médiane
            pairs = []
            for i in range(len(cseqs)):
                for j in range(i+1, len(cseqs)):
                    d = edlib.align(cseqs[i][:p_clust_bytes], cseqs[j][:p_clust_bytes],
                                    mode="NW", task="distance")["editDistance"]
                    pairs.append((d, i, j))
            if not pairs:
                continue

            med = statistics.median([d for d, _, _ in pairs])
            _, im, jm = min(pairs, key=lambda x: abs(x[0]-med))
            a_seq, b_seq = cseqs[im], cseqs[jm]

            # Alignement local HW fenêtre glissante avec params explicites
            yara_strings = []
            seen = set()
            for start in range(0, len(a_seq) - p_win_size + 1, p_win_step):
                window = a_seq[start:start + p_win_size]
                try:
                    res = edlib.align(window, b_seq, mode="HW", task="path")
                except Exception:
                    continue
                if res["editDistance"] < 0:
                    continue
                match_ratio = 1.0 - res["editDistance"] / p_win_size
                if match_ratio < p_min_match:
                    continue
                locs = res.get("locations")
                if not locs:
                    continue
                b_start, b_end = locs[0]
                if b_start in seen:
                    continue
                seen.add(b_start)
                b_region = b_seq[b_start:b_end+1]
                # Appel avec max_gap_size explicite
                new_s = _align_and_build(window, b_region,
                                         max_gap_size=p_max_gap,
                                         min_block_size=p_min_block,
                                         max_block_bytes=p_max_block_bytes)
                yara_strings.extend(new_s)
                if len(yara_strings) >= p_max_strings:
                    break

            yara_strings = mod.filter_yara_strings(yara_strings)
            all_yara_strings.extend(yara_strings)

    except Exception as e:
        import traceback; traceback.print_exc()
        return -1

    elapsed = time.monotonic() - t0
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{family}.yar")

    if not all_yara_strings:
        with open(out_path, 'w') as f:
            f.write(f"// NO SIGNATURE for {family}\n")
        return elapsed

    rule_text = get_lcs_module().build_yara_rule_text(family, all_yara_strings, elapsed)
    with open(out_path, 'w') as f:
        f.write(rule_text)
    return elapsed


def evaluate(family: str, sig_path: str) -> dict:
    if not os.path.exists(sig_path):
        return dict(tp=0, fp=0, recall=0.0, f1=0.0, sig=False)
    with open(sig_path) as f:
        if f.read().strip().startswith('//'):
            return dict(tp=0, fp=0, recall=0.0, f1=0.0, sig=False)
    try:
        rules = yara.compile(sig_path)
    except Exception as e:
        print(f"  [ERREUR compile] {family}: {e}")
        return dict(tp=0, fp=0, recall=0.0, f1=0.0, sig=False)
    test_dir = os.path.join(DATASET_ROOT, 'malware', 'test', family)
    gw_dir   = os.path.join(DATASET_ROOT, 'goodware', 'test')
    tp = sum(1 for f in os.listdir(test_dir) if rules.match(os.path.join(test_dir, f)))
    fp = sum(1 for f in os.listdir(gw_dir)   if rules.match(os.path.join(gw_dir, f)))
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / 25
    f1   = 2*prec*rec / (prec+rec) if (prec+rec) > 0 else 0.0
    return dict(tp=tp, fp=fp, recall=rec, f1=f1, sig=True)


def run_sweep(param: str, values: list, families: list):
    out_base = os.path.join(SIGNATURES_DIR, param)
    os.makedirs(out_base, exist_ok=True)
    csv_path = os.path.join(out_base, f'sweep_{param}.csv')
    rows = []
    header = (['param', 'value'] +
              [f'{f}_tp' for f in families] +
              [f'{f}_fp' for f in families] +
              [f'{f}_f1' for f in families] +
              ['total_tp', 'total_fp', 'avg_recall_pct'])

    print(f"\n{'='*62}")
    print(f"Sweep: {param}  |  Valeurs: {values}")
    print(f"Référence autres params: max_gap={REFERENCE['max_gap_size']} "
          f"theta={REFERENCE['cluster_threshold']} "
          f"rho={REFERENCE['local_min_match_ratio']} "
          f"W={REFERENCE['local_window_size']}")
    print(f"{'='*62}")

    for val in values:
        print(f"\n▶ {param} = {val}")
        params = dict(REFERENCE)
        params[param] = val
        row = {'param': param, 'value': val}
        total_tp = 0; total_fp = 0

        print(f"  {'Famille':<12}  {'Tps':>6}  {'TP/25':>6}  {'FP/500':>7}  {'F1':>5}")
        print(f"  {'-'*44}")

        for family in families:
            sig_dir  = os.path.join(out_base, str(val), family)
            sig_path = os.path.join(sig_dir, f"{family}.yar")
            print(f"  {family:<12}", end='', flush=True)
            t = generate_signature(family, sig_dir, params)
            print(f"  {t:>5.1f}s", end='', flush=True)
            m = evaluate(family, sig_path)
            row[f'{family}_tp'] = m['tp']
            row[f'{family}_fp'] = m['fp']
            row[f'{family}_f1'] = round(m['f1'], 3)
            total_tp += m['tp']; total_fp += m['fp']
            print(f"  {m['tp']:>4}/25  {m['fp']:>5}/500  {m['f1']:>4.2f}"
                  + ('' if m['sig'] else '  (no sig)'))

        avg_recall = total_tp / (len(families) * 25) * 100
        row.update(total_tp=total_tp, total_fp=total_fp,
                   avg_recall_pct=round(avg_recall, 1))
        rows.append(row)
        print(f"  {'─'*44}")
        print(f"  Total: TP={total_tp}/{len(families)*25}  FP={total_fp}  recall={avg_recall:.1f}%")

    with open(csv_path, 'w', newline='') as f:
        csv.DictWriter(f, fieldnames=header).writeheader()
        csv.DictWriter(f, fieldnames=header).writerows(rows)

    print(f"\n✓ CSV: {csv_path}")
    print(f"\n{'='*62}")
    print(f"RÉSUMÉ — {param}")
    print(f"  {'Valeur':>10}  {'TP':>8}  {'FP':>8}  {'Recall':>8}")
    for r in rows:
        print(f"  {r['value']:>10}  {r['total_tp']:>5}/{len(families)*25}  "
              f"{r['total_fp']:>5}/500  {r['avg_recall_pct']:>7.1f}%")
    print(f"{'='*62}\n")
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--param',    required=True, choices=list(REFERENCE.keys()))
    parser.add_argument('--values',   nargs='+', required=True)
    parser.add_argument('--families', nargs='+', default=SWEEP_FAMILIES)
    args = parser.parse_args()
    values = [int(v) if args.param in INT_PARAMS else float(v) for v in args.values]
    run_sweep(args.param, values, args.families)


if __name__ == '__main__':
    main()
