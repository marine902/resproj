"""
param_sweep.py — Automatisation de l'étude de sensibilité des paramètres de lcs_v1.py
Génère les signatures et évalue recall/FP pour chaque valeur de paramètre testé.

Usage:
    python param_sweep.py --param max_gap_size --values 10 20 30 50 75 100
    python param_sweep.py --param cluster_threshold --values 0.3 0.5 0.6 0.7 0.8 0.9
    python param_sweep.py --param local_min_match_ratio --values 0.2 0.3 0.4 0.5 0.6 0.7
    python param_sweep.py --param local_window_size --values 256 512 1024 2048

Le script:
  1. Pour chaque valeur: modifie le paramètre dans lcs_v1.py (en mémoire, sans écrire le fichier)
  2. Génère les signatures pour les familles cibles
  3. Évalue recall + FP
  4. Enregistre les résultats dans sweep_results/<param>/<valeur>.csv

Familles testées (par défaut): neshta, salgorea, blackie
Toutes les autres constantes gardent leurs valeurs originales de lcs_v1.py.
"""

import argparse
import importlib
import sys
import os
import yara
import csv
import time
from types import ModuleType

# ── Familles et chemins ────────────────────────────────────────────────────────
SWEEP_FAMILIES = ['neshta', 'salgorea', 'blackie']
DATASET_ROOT = 'reduced_dataset'
SIGNATURES_DIR = 'signatures_sweep'  # signatures temporaires écrites ici

# ── Valeurs de référence (= valeurs actuelles dans lcs_v1.py) ─────────────────
REFERENCE_VALUES = {
    'max_gap_size':           50,
    'cluster_threshold':      0.8,
    'local_min_match_ratio':  0.4,
    'local_window_size':      1024,
    'local_window_step':      512,
}

# ── Paramètres qui sont des entiers ───────────────────────────────────────────
INT_PARAMS = {'max_gap_size', 'local_window_size', 'local_window_step', 'min_block_size',
              'max_block_bytes', 'max_strings_per_cluster', 'cluster_sample_bytes'}


def load_lcs_module(param_overrides: dict) -> ModuleType:
    """
    Charge lcs_v1.py comme module Python et écrase les constantes indiquées.
    Utilise importlib pour forcer le rechargement à chaque appel.
    """
    # Supprimer le cache si déjà chargé
    if 'lcs_v1' in sys.modules:
        del sys.modules['lcs_v1']

    # Ajouter le répertoire courant au path si nécessaire
    cwd = os.path.dirname(os.path.abspath(__file__))
    if cwd not in sys.path:
        sys.path.insert(0, cwd)

    mod = importlib.import_module('lcs_v1')

    # Écraser les constantes
    for param, value in param_overrides.items():
        if hasattr(mod, param):
            setattr(mod, param, value)
        else:
            raise ValueError(f"Paramètre '{param}' introuvable dans lcs_v1.py")

    return mod


def generate_signature(mod: ModuleType, family: str, out_dir: str) -> float:
    """
    Génère la signature YARA pour une famille en appelant directement les fonctions de lcs_v1.
    Retourne le temps de génération en secondes, ou -1 si échec.
    """
    import logging
    import edlib
    import statistics

    logger = logging.getLogger(f"sweep_{family}")
    logger.setLevel(logging.WARNING)

    training_dir = os.path.join(DATASET_ROOT, 'malware', 'training', family)
    if not os.path.isdir(training_dir):
        print(f"  [ERREUR] Dossier introuvable: {training_dir}")
        return -1

    t0 = time.monotonic()

    try:
        sequences = mod.collect_samples(training_dir, mod.TRUNCATE_BYTES_DEFAULT, logger)
        clusters = mod.cluster_samples(sequences, logger)

        all_yara_strings = []
        for cluster in clusters:
            cluster_sequences = [sequences[i] for i in cluster]

            pairs = []
            for i in range(len(cluster_sequences)):
                for j in range(i+1, len(cluster_sequences)):
                    d = edlib.align(
                        cluster_sequences[i][:mod.cluster_sample_bytes],
                        cluster_sequences[j][:mod.cluster_sample_bytes],
                        mode="NW", task="distance"
                    )["editDistance"]
                    pairs.append((d, i, j))

            if len(pairs) == 0:
                yara_strings = []
            else:
                medianne = statistics.median([d for d, i, j in pairs])
                best_pair = min(pairs, key=lambda x: abs(x[0]-medianne))
                _, im, jm = best_pair
                yara_strings = mod.local_align_and_build_yara_strings(
                    cluster_sequences[im], cluster_sequences[jm]
                )
                yara_strings = mod.filter_yara_strings(yara_strings)

            all_yara_strings.extend(yara_strings)

    except Exception as e:
        print(f"  [ERREUR] génération {family}: {e}")
        return -1

    elapsed = time.monotonic() - t0

    # Écrire la signature
    family_out_dir = os.path.join(out_dir, family)
    os.makedirs(family_out_dir, exist_ok=True)
    out_path = os.path.join(family_out_dir, f"{family}.yar")

    if not all_yara_strings:
        # Écrire un fichier vide marqué
        with open(out_path, 'w') as f:
            f.write(f"// NO SIGNATURE for {family}\n")
        return elapsed

    rule_text = mod.build_yara_rule_text(family, all_yara_strings, elapsed)
    with open(out_path, 'w') as f:
        f.write(rule_text)

    return elapsed


def evaluate_family(family: str, sig_dir: str) -> dict:
    """
    Évalue recall (TP/25) et FP sur goodware (FP/500) pour une famille.
    Retourne un dict avec tp, fp, recall, f1.
    """
    yar_path = os.path.join(sig_dir, family, f"{family}.yar")
    if not os.path.exists(yar_path):
        return {'tp': 0, 'fp': 0, 'recall': 0.0, 'f1': 0.0, 'sig': False}

    # Vérifier que c'est pas juste un commentaire "NO SIGNATURE"
    with open(yar_path) as f:
        content = f.read()
    if content.strip().startswith('//'):
        return {'tp': 0, 'fp': 0, 'recall': 0.0, 'f1': 0.0, 'sig': False}

    try:
        rules = yara.compile(yar_path)
    except Exception as e:
        print(f"  [ERREUR] compile {family}: {e}")
        return {'tp': 0, 'fp': 0, 'recall': 0.0, 'f1': 0.0, 'sig': False}

    test_dir = os.path.join(DATASET_ROOT, 'malware', 'test', family)
    gw_dir = os.path.join(DATASET_ROOT, 'goodware', 'test')

    tp = sum(1 for f in os.listdir(test_dir)
             if rules.match(os.path.join(test_dir, f)))

    fp = sum(1 for f in os.listdir(gw_dir)
             if rules.match(os.path.join(gw_dir, f)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / 25
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {'tp': tp, 'fp': fp, 'recall': recall, 'f1': f1, 'sig': True}


def run_sweep(param: str, values: list, families: list):
    """Lance le sweep complet pour un paramètre donné."""

    results_dir = os.path.join('sweep_results', param)
    os.makedirs(results_dir, exist_ok=True)

    # CSV de sortie
    csv_path = os.path.join(results_dir, f'sweep_{param}.csv')
    rows = []

    print(f"\n{'='*60}")
    print(f"Sweep: {param}")
    print(f"Valeurs: {values}")
    print(f"Familles: {families}")
    print(f"{'='*60}")

    # Header
    header = ['param', 'value'] + [f'{fam}_tp' for fam in families] + \
             [f'{fam}_fp' for fam in families] + [f'{fam}_f1' for fam in families] + \
             ['total_tp', 'total_fp', 'avg_recall_pct']

    for val in values:
        val_float = float(val) if param not in INT_PARAMS else int(val)
        print(f"\n▶ {param} = {val_float}")

        # Construire les overrides: toutes les valeurs de référence + la valeur testée
        overrides = dict(REFERENCE_VALUES)
        overrides[param] = val_float

        # Charger le module avec les overrides
        try:
            mod = load_lcs_module(overrides)
        except Exception as e:
            print(f"  [ERREUR] chargement module: {e}")
            continue

        # Dossier de signatures pour cette valeur
        sig_dir = os.path.join(SIGNATURES_DIR, param, str(val))

        # Générer les signatures
        gen_times = {}
        for family in families:
            print(f"  → Génération {family}...", end='', flush=True)
            t = generate_signature(mod, family, sig_dir)
            gen_times[family] = t
            print(f" {t:.1f}s")

        # Évaluer
        row = {'param': param, 'value': val_float}
        total_tp = 0
        total_fp = 0

        print(f"  {'Famille':<12} {'TP/25':>6} {'FP/500':>7} {'F1':>5}")
        print(f"  {'-'*34}")

        for family in families:
            metrics = evaluate_family(family, sig_dir)
            row[f'{family}_tp'] = metrics['tp']
            row[f'{family}_fp'] = metrics['fp']
            row[f'{family}_f1'] = round(metrics['f1'], 3)
            total_tp += metrics['tp']
            total_fp += metrics['fp']
            sig_str = '' if metrics['sig'] else ' (no sig)'
            print(f"  {family:<12} {metrics['tp']:>4}/25  {metrics['fp']:>5}/500  {metrics['f1']:>4.2f}{sig_str}")

        row['total_tp'] = total_tp
        row['total_fp'] = total_fp
        avg_recall = total_tp / (len(families) * 25) * 100
        row['avg_recall_pct'] = round(avg_recall, 1)

        print(f"  {'─'*34}")
        print(f"  Total: TP={total_tp}/{len(families)*25}  FP={total_fp}  recall={avg_recall:.1f}%")
        rows.append(row)

    # Écrire le CSV
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n✓ Résultats sauvegardés dans: {csv_path}")
    print(f"\n{'='*60}")
    print(f"RÉSUMÉ — {param}")
    print(f"{'─'*60}")
    print(f"{'Valeur':>10}  {'TP total':>9}  {'FP total':>9}  {'Recall':>7}")
    for row in rows:
        print(f"  {row['value']:>8}  {row['total_tp']:>7}/{len(families)*25}  {row['total_fp']:>7}/500  {row['avg_recall_pct']:>6.1f}%")
    print(f"{'='*60}")

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
        help='Valeurs à tester (ex: 10 20 30 50 75 100)'
    )
    parser.add_argument(
        '--families', nargs='+', default=SWEEP_FAMILIES,
        help=f'Familles à tester (défaut: {SWEEP_FAMILIES})'
    )

    args = parser.parse_args()

    # Convertir les valeurs
    if args.param in INT_PARAMS:
        values = [int(v) for v in args.values]
    else:
        values = [float(v) for v in args.values]

    run_sweep(args.param, values, args.families)


if __name__ == '__main__':
    main()
