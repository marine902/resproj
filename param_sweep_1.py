"""
param_sweep.py — Sweep automatique des paramètres de lcs_v1.py
Stratégie : réécrire lcs_v1.py avec la nouvelle valeur, importer, générer, restaurer.

Usage:
    python param_sweep.py --param max_gap_size --values 10 20 30 50 75 100
    python param_sweep.py --param cluster_threshold --values 0.3 0.5 0.6 0.7 0.8 0.9
    python param_sweep.py --param local_min_match_ratio --values 0.2 0.3 0.4 0.5 0.6 0.7
    python param_sweep.py --param local_window_size --values 256 512 1024 2048
"""

import argparse
import importlib
import sys
import os
import re
import yara
import csv
import time
import shutil
import logging

# ── Config ────────────────────────────────────────────────────────────────────
SWEEP_FAMILIES = ['neshta', 'salgorea', 'blackie']
DATASET_ROOT   = 'reduced_dataset'
SIGNATURES_DIR = 'signatures_sweep'
LCS_FILE       = 'lcs_v1.py'
LCS_BACKUP     = 'lcs_v1_backup_sweep.py'

# Valeurs de référence = valeurs actuelles dans le code
REFERENCE_VALUES = {
    'max_gap_size':          50,
    'cluster_threshold':     0.8,
    'local_min_match_ratio': 0.4,
    'local_window_size':     1024,
    'local_window_step':     512,
}

# Pattern de remplacement pour chaque paramètre :
# on cherche la ligne `NOM=VALEUR` et on remplace par `NOM=NOUVELLE_VALEUR`
PARAM_PATTERNS = {
    'max_gap_size':          r'^(max_gap_size\s*=\s*)[\d.]+',
    'cluster_threshold':     r'^(cluster_threshold\s*=\s*)[\d.]+',
    'local_min_match_ratio': r'^(local_min_match_ratio\s*=\s*)[\d.]+',
    'local_window_size':     r'^(local_window_size\s*=\s*)[\d.]+',
    'local_window_step':     r'^(local_window_step\s*=\s*)[\d.]+',
}

INT_PARAMS = {'max_gap_size', 'local_window_size', 'local_window_step'}


def patch_lcs_file(param: str, value) -> bool:
    """Modifie lcs_v1.py en remplaçant la valeur du paramètre."""
    pattern = PARAM_PATTERNS[param]
    
    with open(LCS_FILE, 'r') as f:
        lines = f.readlines()
    
    found = False
    new_lines = []
    for line in lines:
        m = re.match(pattern, line)
        if m and not found:
            # Remplacer la valeur, garder le reste de la ligne (commentaires)
            rest = line[m.end():]  # tout ce qui suit la valeur (commentaire éventuel)
            new_line = m.group(1) + str(value) + rest
            new_lines.append(new_line)
            found = True
        else:
            new_lines.append(line)
    
    if not found:
        print(f"  [ERREUR] Pattern non trouvé pour '{param}' dans {LCS_FILE}")
        return False
    
    with open(LCS_FILE, 'w') as f:
        f.writelines(new_lines)
    
    return True


def load_lcs_fresh():
    """Force le rechargement complet de lcs_v1 depuis le fichier."""
    # Supprimer tous les modules qui pourraient cacher une ancienne version
    to_del = [k for k in sys.modules if k.startswith('lcs_v1')]
    for k in to_del:
        del sys.modules[k]
    
    cwd = os.path.dirname(os.path.abspath(LCS_FILE))
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    
    return importlib.import_module('lcs_v1')


def generate_signature(mod, family: str, out_dir: str) -> float:
    """Génère la signature YARA pour une famille. Retourne le temps en secondes."""
    import edlib
    import statistics as stats_mod

    logger = logging.getLogger('sweep')
    logger.setLevel(logging.WARNING)

    training_dir = os.path.join(DATASET_ROOT, 'malware', 'training', family)
    if not os.path.isdir(training_dir):
        print(f"  [ERREUR] Dossier introuvable: {training_dir}")
        return -1.0

    t0 = time.monotonic()
    try:
        sequences = mod.collect_samples(training_dir, mod.TRUNCATE_BYTES_DEFAULT, logger)
        clusters = mod.cluster_samples(sequences, logger)

        all_yara_strings = []
        for cluster in clusters:
            cluster_seqs = [sequences[i] for i in cluster]

            pairs = []
            for i in range(len(cluster_seqs)):
                for j in range(i+1, len(cluster_seqs)):
                    d = edlib.align(
                        cluster_seqs[i][:mod.cluster_sample_bytes],
                        cluster_seqs[j][:mod.cluster_sample_bytes],
                        mode="NW", task="distance"
                    )["editDistance"]
                    pairs.append((d, i, j))

            if len(pairs) == 0:
                yara_strings = []
            else:
                med = stats_mod.median([d for d, i, j in pairs])
                best = min(pairs, key=lambda x: abs(x[0]-med))
                _, im, jm = best
                yara_strings = mod.local_align_and_build_yara_strings(
                    cluster_seqs[im], cluster_seqs[jm]
                )
                yara_strings = mod.filter_yara_strings(yara_strings)

            all_yara_strings.extend(yara_strings)

    except Exception as e:
        print(f"  [ERREUR] {family}: {e}")
        return -1.0

    elapsed = time.monotonic() - t0

    family_out = os.path.join(out_dir, family)
    os.makedirs(family_out, exist_ok=True)
    out_path = os.path.join(family_out, f"{family}.yar")

    if not all_yara_strings:
        with open(out_path, 'w') as f:
            f.write(f"// NO SIGNATURE\n")
        return elapsed

    rule_text = mod.build_yara_rule_text(family, all_yara_strings, elapsed)
    with open(out_path, 'w') as f:
        f.write(rule_text)

    return elapsed


def evaluate_family(family: str, sig_dir: str) -> dict:
    """Évalue TP/25 et FP/500 pour une famille."""
    yar_path = os.path.join(sig_dir, family, f"{family}.yar")
    if not os.path.exists(yar_path):
        return {'tp': 0, 'fp': 0, 'recall': 0.0, 'f1': 0.0, 'sig': False}

    with open(yar_path) as f:
        if f.read().strip().startswith('//'):
            return {'tp': 0, 'fp': 0, 'recall': 0.0, 'f1': 0.0, 'sig': False}

    try:
        rules = yara.compile(yar_path)
    except Exception as e:
        print(f"  [ERREUR compile] {family}: {e}")
        return {'tp': 0, 'fp': 0, 'recall': 0.0, 'f1': 0.0, 'sig': False}

    test_dir = os.path.join(DATASET_ROOT, 'malware', 'test', family)
    gw_dir   = os.path.join(DATASET_ROOT, 'goodware', 'test')

    tp = sum(1 for f in os.listdir(test_dir)
             if rules.match(os.path.join(test_dir, f)))
    fp = sum(1 for f in os.listdir(gw_dir)
             if rules.match(os.path.join(gw_dir, f)))

    prec  = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec   = tp / 25
    f1    = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

    return {'tp': tp, 'fp': fp, 'recall': rec, 'f1': f1, 'sig': True}


def run_sweep(param: str, values: list, families: list):
    """Lance le sweep complet pour un paramètre."""

    # Sauvegarde du fichier original
    shutil.copy2(LCS_FILE, LCS_BACKUP)
    print(f"Sauvegarde créée: {LCS_BACKUP}")

    results_dir = os.path.join('sweep_results', param)
    os.makedirs(results_dir, exist_ok=True)
    csv_path = os.path.join(results_dir, f'sweep_{param}.csv')

    header = (['param', 'value']
              + [f'{fam}_tp' for fam in families]
              + [f'{fam}_fp' for fam in families]
              + [f'{fam}_f1' for fam in families]
              + ['total_tp', 'total_fp', 'avg_recall_pct'])
    rows = []

    print(f"\n{'='*60}")
    print(f"Sweep: {param}")
    print(f"Valeurs: {values}")
    print(f"Familles: {families}")
    print(f"Référence des autres paramètres: {REFERENCE_VALUES}")
    print(f"{'='*60}")

    try:
        for val in values:
            print(f"\n▶ {param} = {val}")

            # 1. Patcher le fichier avec la nouvelle valeur
            if not patch_lcs_file(param, val):
                print(f"  [SKIP] patch échoué pour {val}")
                continue

            # 2. Vérification rapide que le patch a bien fonctionné
            with open(LCS_FILE) as f:
                content = f.read()
            pattern = PARAM_PATTERNS[param]
            m = re.search(pattern, content, re.MULTILINE)
            if m:
                print(f"  ✓ Patch confirmé: '{m.group(0).strip()}'")
            else:
                print(f"  [ATTENTION] Patch non vérifié")

            # 3. Recharger le module depuis le fichier modifié
            mod = load_lcs_fresh()

            # Vérifier que la valeur est bien chargée
            actual = getattr(mod, param, None)
            print(f"  ✓ Valeur chargée dans le module: {param} = {actual}")

            # 4. Dossier de signatures pour cette valeur
            sig_dir = os.path.join(SIGNATURES_DIR, param, str(val))

            # 5. Générer les signatures
            for family in families:
                print(f"  → Génération {family}...", end='', flush=True)
                t = generate_signature(mod, family, sig_dir)
                print(f" {t:.1f}s")

            # 6. Évaluer
            row = {'param': param, 'value': val}
            total_tp = 0
            total_fp = 0

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
            avg_recall            = total_tp / (len(families) * 25) * 100
            row['avg_recall_pct'] = round(avg_recall, 1)
            rows.append(row)

            print(f"  {'─'*36}")
            print(f"  Total: TP={total_tp}/{len(families)*25}  FP={total_fp}  recall={avg_recall:.1f}%")

            # 7. Remettre la valeur de référence avant la prochaine itération
            ref_val = REFERENCE_VALUES[param]
            patch_lcs_file(param, ref_val)

    finally:
        # Restaurer le fichier original dans tous les cas
        shutil.copy2(LCS_BACKUP, LCS_FILE)
        os.remove(LCS_BACKUP)
        print(f"\n✓ lcs_v1.py restauré à son état original")

    # Écrire le CSV
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)

    # Résumé final
    print(f"\n{'='*60}")
    print(f"RÉSUMÉ — {param}")
    print(f"{'─'*60}")
    print(f"{'Valeur':>10}  {'TP total':>9}  {'FP total':>9}  {'Recall':>7}")
    for row in rows:
        print(f"  {row['value']:>8}  {row['total_tp']:>7}/{len(families)*25}  "
              f"{row['total_fp']:>7}/500  {row['avg_recall_pct']:>6.1f}%")
    print(f"{'='*60}")
    print(f"\n✓ CSV sauvegardé: {csv_path}")

    return rows


def main():
    parser = argparse.ArgumentParser(
        description="Sweep automatique de paramètres pour lcs_v1.py"
    )
    parser.add_argument(
        '--param', required=True,
        choices=list(REFERENCE_VALUES.keys()),
        help='Paramètre à faire varier'
    )
    parser.add_argument(
        '--values', nargs='+', required=True,
        help='Valeurs à tester'
    )
    parser.add_argument(
        '--families', nargs='+', default=SWEEP_FAMILIES,
        help=f'Familles cibles (défaut: {SWEEP_FAMILIES})'
    )
    args = parser.parse_args()

    if args.param in INT_PARAMS:
        values = [int(v) for v in args.values]
    else:
        values = [float(v) for v in args.values]

    run_sweep(args.param, values, args.families)


if __name__ == '__main__':
    main()
