"""
param_sweep.py v3 — Sweep paramètres lcs_v1.py
Contourne le problème des valeurs par défaut gelées en passant les paramètres
EXPLICITEMENT à chaque appel de fonction.

Usage:
    python param_sweep.py --param local_min_match_ratio --values 0.2 0.3 0.4 0.5 0.6 0.7
    python param_sweep.py --param local_window_size --values 256 512 1024 2048
    python param_sweep.py --param cluster_threshold --values 0.3 0.5 0.6 0.7 0.8 0.9
    python param_sweep.py --param max_gap_size --values 10 20 30 50 75 100
"""

import argparse, os, sys, csv, time, logging, re, shutil
import edlib, yara, statistics as stats_mod

# ── Config ────────────────────────────────────────────────────────────────────
SWEEP_FAMILIES = ['neshta', 'salgorea', 'blackie']
DATASET_ROOT   = 'reduced_dataset'
SIGNATURES_DIR = 'signatures_sweep'

# Valeurs de référence (ne changent pas quand on sweepé un autre paramètre)
REF = {
    'max_gap_size':          50,
    'cluster_threshold':     0.8,
    'local_min_match_ratio': 0.4,
    'local_window_size':     1024,
    'local_window_step':     512,
    'min_block_size':        16,
    'max_block_bytes':       500,
    'max_strings_per_cluster': 20,
    'cluster_sample_bytes':  10000,
    'TRUNCATE_BYTES_DEFAULT': 1000000,
}

INT_PARAMS = {'max_gap_size', 'local_window_size', 'local_window_step',
              'min_block_size', 'max_block_bytes', 'max_strings_per_cluster',
              'cluster_sample_bytes'}

# ── Copie locale des fonctions de lcs_v1 ─────────────────────────────────────
# On copie lcs_v1.py une fois au départ, puis on appelle les fonctions
# directement avec les paramètres passés explicitement.

sys.path.insert(0, os.path.dirname(os.path.abspath('lcs_v1.py')))
import lcs_v1 as _lcs


# ── Fonctions clés réécrites pour accepter les params explicitement ───────────

def cluster_samples(sequences, cluster_threshold, cluster_sample_bytes, logger):
    """Union-Find clustering avec seuil et taille de préfixe passés explicitement."""
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
    logger.info(f"Clustering: {len(result)} clusters")
    return result


def align_and_build_yara_strings(a, b, max_gap_size, max_block_bytes, min_block_size):
    """Construction YARA depuis CIGAR avec max_gap_size passé explicitement."""
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
    gap_min = gap_max = 0
    i = 0

    def flush_gap():
        nonlocal in_gap, gap_min, gap_max
        if in_gap:
            current_string.append(f"[{gap_min}-{gap_max}]")
            in_gap = False
            gap_min = gap_max = 0

    def flush_block():
        nonlocal current_string, current_len, in_gap, gap_min, gap_max
        if in_gap:
            in_gap = False; gap_min = gap_max = 0
        if current_len >= min_block_size:
            tokens = current_string[:]
            while tokens and tokens[0][0] == '[': tokens.pop(0)
            while tokens and tokens[-1][0] == '[': tokens.pop()
            bc = sum(1 for t in tokens if t[0] != '[')
            if bc >= min_block_size:
                strings.append("{ " + " ".join(tokens) + " }")
        current_string.clear()
        current_len = 0

    for op, count in operations:
        if i >= len(a): break
        if op == "=":
            flush_gap()
            safe = min(count, len(a)-i)
            rem, pos = safe, i
            while rem > 0:
                space = max_block_bytes - current_len
                chunk = min(space, rem)
                for k in range(chunk):
                    current_string.append(f"{a[pos+k]:02x}")
                current_len += chunk; pos += chunk; rem -= chunk
                if current_len >= max_block_bytes:
                    flush_block()
            i += safe
        elif op == "X":
            safe = min(count, len(a)-i)
            if safe > max_gap_size:
                flush_block()
            else:
                if not in_gap: in_gap=True; gap_min=gap_max=safe
                else: gap_min+=safe; gap_max+=safe
            i += safe
        elif op == "D":
            safe = min(count, len(a)-i)
            if safe > max_gap_size:
                flush_block()
            else:
                if not in_gap: in_gap=True; gap_min=0; gap_max=safe
                else: gap_max+=safe
            i += safe
        elif op == "I":
            if count > max_gap_size:
                flush_block()
            else:
                if not in_gap: in_gap=True; gap_min=0; gap_max=count
                else: gap_max+=count
    flush_block()
    return strings


def local_align_and_build_yara_strings(a, b, window_size, window_step,
                                        min_match_ratio, max_gap_size,
                                        max_block_bytes, min_block_size,
                                        max_strings_per_cluster):
    """Alignement local fenêtre glissante avec TOUS les params passés explicitement."""
    strings = []
    seen_offsets = set()

    for start in range(0, len(a) - window_size + 1, window_step):
        window = a[start:start+window_size]
        try:
            result = edlib.align(window, b, mode="HW", task="path")
        except Exception:
            continue
        if result["editDistance"] < 0:
            continue

        match_ratio = 1.0 - result["editDistance"] / window_size
        if match_ratio < min_match_ratio:
            continue

        locs = result.get("locations")
        if not locs:
            continue
        b_start, b_end = locs[0]
        if b_start in seen_offsets:
            continue
        seen_offsets.add(b_start)

        b_region = b[b_start:b_end+1]
        new_strings = align_and_build_yara_strings(
            window, b_region, max_gap_size, max_block_bytes, min_block_size
        )
        strings.extend(new_strings)
        if len(strings) >= max_strings_per_cluster:
            break

    return strings


# ── Pipeline principal ────────────────────────────────────────────────────────

def generate_signature(family, sig_dir, params):
    """Génère une signature YARA pour une famille avec les params donnés."""
    logger = logging.getLogger('sweep')
    logger.setLevel(logging.WARNING)

    training_dir = os.path.join(DATASET_ROOT, 'malware', 'training', family)
    if not os.path.isdir(training_dir):
        print(f"  [ERREUR] Dossier introuvable: {training_dir}")
        return -1.0

    t0 = time.monotonic()
    try:
        sequences = _lcs.collect_samples(training_dir, params['TRUNCATE_BYTES_DEFAULT'], logger)

        clusters = cluster_samples(
            sequences,
            cluster_threshold=params['cluster_threshold'],
            cluster_sample_bytes=params['cluster_sample_bytes'],
            logger=logger
        )

        all_yara_strings = []
        for cluster in clusters:
            cluster_seqs = [sequences[i] for i in cluster]

            pairs = []
            for i in range(len(cluster_seqs)):
                for j in range(i+1, len(cluster_seqs)):
                    d = edlib.align(
                        cluster_seqs[i][:params['cluster_sample_bytes']],
                        cluster_seqs[j][:params['cluster_sample_bytes']],
                        mode="NW", task="distance"
                    )["editDistance"]
                    pairs.append((d, i, j))

            if not pairs:
                continue

            med = stats_mod.median([d for d, i, j in pairs])
            best = min(pairs, key=lambda x: abs(x[0]-med))
            _, im, jm = best

            yara_strings = local_align_and_build_yara_strings(
                cluster_seqs[im], cluster_seqs[jm],
                window_size=params['local_window_size'],
                window_step=params['local_window_step'],
                min_match_ratio=params['local_min_match_ratio'],
                max_gap_size=params['max_gap_size'],
                max_block_bytes=params['max_block_bytes'],
                min_block_size=params['min_block_size'],
                max_strings_per_cluster=params['max_strings_per_cluster'],
            )
            yara_strings = _lcs.filter_yara_strings(yara_strings)
            all_yara_strings.extend(yara_strings)

    except Exception as e:
        import traceback; traceback.print_exc()
        print(f"  [ERREUR] {family}: {e}")
        return -1.0

    elapsed = time.monotonic() - t0

    family_out = os.path.join(sig_dir, family)
    os.makedirs(family_out, exist_ok=True)
    out_path = os.path.join(family_out, f"{family}.yar")

    if not all_yara_strings:
        with open(out_path, 'w') as f:
            f.write("// NO SIGNATURE\n")
        return elapsed

    rule_text = _lcs.build_yara_rule_text(family, all_yara_strings, elapsed)
    with open(out_path, 'w') as f:
        f.write(rule_text)
    return elapsed


def evaluate_family(family, sig_dir):
    yar_path = os.path.join(sig_dir, family, f"{family}.yar")
    if not os.path.exists(yar_path):
        return {'tp': 0, 'fp': 0, 'f1': 0.0, 'sig': False}
    with open(yar_path) as f:
        if f.read().strip().startswith('//'):
            return {'tp': 0, 'fp': 0, 'f1': 0.0, 'sig': False}
    try:
        rules = yara.compile(yar_path)
    except Exception as e:
        print(f"  [compile error] {family}: {e}")
        return {'tp': 0, 'fp': 0, 'f1': 0.0, 'sig': False}

    test_dir = os.path.join(DATASET_ROOT, 'malware', 'test', family)
    gw_dir   = os.path.join(DATASET_ROOT, 'goodware', 'test')
    tp = sum(1 for f in os.listdir(test_dir) if rules.match(os.path.join(test_dir, f)))
    fp = sum(1 for f in os.listdir(gw_dir)   if rules.match(os.path.join(gw_dir, f)))
    prec = tp/(tp+fp) if (tp+fp) > 0 else 0.0
    rec  = tp/25
    f1   = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0.0
    return {'tp': tp, 'fp': fp, 'f1': f1, 'sig': True}


# ── Sweep ─────────────────────────────────────────────────────────────────────

def run_sweep(param, values, families):
    os.makedirs(os.path.join('sweep_results', param), exist_ok=True)
    csv_path = os.path.join('sweep_results', param, f'sweep_{param}.csv')

    header = (['param', 'value']
              + [f'{f}_tp' for f in families]
              + [f'{f}_fp' for f in families]
              + [f'{f}_f1' for f in families]
              + ['total_tp', 'total_fp', 'avg_recall_pct'])
    rows = []

    print(f"\n{'='*60}")
    print(f"Sweep: {param}  |  Valeurs: {values}")
    print(f"Familles: {families}")
    print(f"Référence: { {k:v for k,v in REF.items() if k in ['max_gap_size','cluster_threshold','local_min_match_ratio','local_window_size','local_window_step']} }")
    print(f"{'='*60}")

    for val in values:
        print(f"\n▶ {param} = {val}")

        # Construire le dict de paramètres : référence + valeur testée
        params = dict(REF)
        params[param] = val

        sig_dir = os.path.join(SIGNATURES_DIR, param, str(val))

        for family in families:
            print(f"  → {family}...", end='', flush=True)
            t = generate_signature(family, sig_dir, params)
            print(f" {t:.1f}s")

        row = {'param': param, 'value': val}
        total_tp = total_fp = 0

        print(f"  {'Famille':<12} {'TP/25':>6} {'FP/500':>7} {'F1':>5}")
        print(f"  {'-'*36}")
        for family in families:
            m = evaluate_family(family, sig_dir)
            row[f'{family}_tp'] = m['tp']
            row[f'{family}_fp'] = m['fp']
            row[f'{family}_f1'] = round(m['f1'], 3)
            total_tp += m['tp']
            total_fp += m['fp']
            tag = '' if m['sig'] else ' (no sig)'
            print(f"  {family:<12} {m['tp']:>4}/25  {m['fp']:>5}/500  {m['f1']:>4.2f}{tag}")

        row['total_tp']       = total_tp
        row['total_fp']       = total_fp
        avg_recall            = total_tp / (len(families)*25) * 100
        row['avg_recall_pct'] = round(avg_recall, 1)
        rows.append(row)
        print(f"  {'─'*36}")
        print(f"  Total TP={total_tp}/{len(families)*25}  FP={total_fp}  recall={avg_recall:.1f}%")

    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n{'='*60}")
    print(f"RÉSUMÉ — {param}")
    print(f"{'─'*60}")
    print(f"{'Valeur':>10}  {'TP':>8}  {'FP':>8}  {'Recall':>7}")
    for row in rows:
        print(f"  {row['value']:>8}  {row['total_tp']:>6}/{len(families)*25}  "
              f"{row['total_fp']:>6}/500  {row['avg_recall_pct']:>6.1f}%")
    print(f"{'='*60}")
    print(f"CSV: {csv_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--param', required=True, choices=list(REF.keys()))
    ap.add_argument('--values', nargs='+', required=True)
    ap.add_argument('--families', nargs='+', default=SWEEP_FAMILIES)
    args = ap.parse_args()

    values = [int(v) if args.param in INT_PARAMS else float(v) for v in args.values]
    run_sweep(args.param, values, args.families)


if __name__ == '__main__':
    main()
