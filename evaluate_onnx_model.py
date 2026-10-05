"""
Evalúa firewall_edge_model.onnx contra todos los CSV de CIC-IDS2017.

Usa onnxruntime (el mismo motor que correrá en el dispositivo edge), así que
se prueba exactamente el binario exportado y no el modelo de Python.

Uso:
    python3 evaluate_onnx_model.py [carpeta_csv] [modelo.onnx]
"""
import sys
import glob
import os

import numpy as np
import pandas as pd
import onnxruntime as ort

from train_edge_model import SELECTED_FEATURES, TARGET_COLUMN

DEFAULT_CSV_DIR = "/home/valenturas_cardenas/Descargas/NSL-KDD/MachineLearningCSV/MachineLearningCVE"
DEFAULT_MODEL = "firewall_edge_model.onnx"
TRAIN_FILE = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"


def load_csv(path):
    # latin-1: algunos labels (Web Attack – ...) traen bytes que no son UTF-8 válido
    df = pd.read_csv(path, usecols=SELECTED_FEATURES + [TARGET_COLUMN],
                     encoding="latin-1", low_memory=False)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df[TARGET_COLUMN] = df[TARGET_COLUMN].str.strip()
    X = df[SELECTED_FEATURES].to_numpy(dtype=np.float32)
    y = (df[TARGET_COLUMN] != "BENIGN").astype(np.int8).to_numpy()
    return X, y, df[TARGET_COLUMN].to_numpy()


def evaluate_file(sess, input_name, path):
    X, y, labels = load_csv(path)
    y_pred = sess.run(None, {input_name: X})[0].astype(np.int8)

    benign = y == 0
    attack = y == 1
    fp_rate = (y_pred[benign] == 1).mean() if benign.any() else float("nan")
    det_rate = (y_pred[attack] == 1).mean() if attack.any() else float("nan")
    acc = (y_pred == y).mean()

    # Tasa de detección por tipo de ataque
    per_label = {}
    for lbl in np.unique(labels):
        mask = labels == lbl
        hit = (y_pred[mask] == 1).mean() if lbl != "BENIGN" else (y_pred[mask] == 0).mean()
        per_label[lbl] = (mask.sum(), hit)

    return {"rows": len(y), "acc": acc, "fp_rate": fp_rate,
            "det_rate": det_rate, "per_label": per_label}


def main():
    csv_dir = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CSV_DIR
    model_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_MODEL

    sess = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
    input_name = sess.get_inputs()[0].name

    files = sorted(glob.glob(os.path.join(csv_dir, "*.csv")))
    if not files:
        print(f"No se encontraron CSV en {csv_dir}")
        return

    summary = []
    for path in files:
        name = os.path.basename(path)
        tag = "  (ENTRENAMIENTO)" if name == TRAIN_FILE else ""
        print(f"\n=== {name}{tag}")
        r = evaluate_file(sess, input_name, path)
        print(f"Filas: {r['rows']:,} | Accuracy: {r['acc']:.4f} | "
              f"Falsos positivos (benigno->ataque): {r['fp_rate']:.4f} | "
              f"Detección de ataques: {r['det_rate']:.4f}")
        print(f"  {'Etiqueta':<35}{'Filas':>10}{'Acierto':>10}")
        for lbl, (n, hit) in sorted(r["per_label"].items(), key=lambda kv: -kv[1][0]):
            print(f"  {lbl:<35}{n:>10,}{hit:>10.4f}")
        summary.append((name, tag, r))

    print("\n" + "=" * 100)
    print(f"{'Archivo':<60}{'Accuracy':>10}{'FP rate':>10}{'Detección':>12}")
    for name, tag, r in summary:
        print(f"{name[:58] + ('*' if tag else ''):<60}{r['acc']:>10.4f}"
              f"{r['fp_rate']:>10.4f}{r['det_rate']:>12.4f}")
    print("* = archivo usado para entrenar (sus resultados no cuentan como prueba real)")


if __name__ == "__main__":
    main()
