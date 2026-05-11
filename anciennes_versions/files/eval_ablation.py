"""
Script d'évaluation pour l'étude d'ablation.
Calcule recall, FP et F1 pour chaque config A1..A5.
Usage: python3 eval_ablation.py
"""
import yara, os

families = ['berbew','blackie','doina','ibryte','neshta','pidgeon','salgorea','softcnapp','symmi','virut']
configs = ['A1', 'A2', 'A3', 'A4', 'A5']

print(f"{'Config':<6} {'Famille':<12} {'TP/25':<8} {'FP/500':<8} {'F1':<6}")
print("-" * 44)

for config in configs:
    total_tp = 0
    total_fp = 0
    total_families = 0

    for fam in families:
        yar = f'signatures_ablation/{config}/{fam}/{fam}.yar'
        if not os.path.exists(yar):
            print(f"{config:<6} {fam:<12} no sig")
            continue
        try:
            rules = yara.compile(yar)
        except Exception as e:
            print(f"{config:<6} {fam:<12} compile error: {e}")
            continue

        tp = sum(1 for f in os.listdir(f'reduced_dataset/malware/test/{fam}')
                 if rules.match(f'reduced_dataset/malware/test/{fam}/{f}'))
        fp = sum(1 for f in os.listdir('reduced_dataset/goodware/test')
                 if rules.match(f'reduced_dataset/goodware/test/{f}'))

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / 25
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        total_tp += tp
        total_fp += fp
        total_families += 1

        print(f"{config:<6} {fam:<12} {tp}/25    {fp}/500   {f1:.2f}")

    recall_pct = total_tp / (total_families * 25) * 100 if total_families > 0 else 0
    print(f"{config:<6} {'TOTAL':<12} {total_tp}/{total_families*25} {total_fp}/500  recall={recall_pct:.1f}%")
    print()
