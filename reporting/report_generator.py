import os
import json
from datetime import datetime

import matplotlib
matplotlib.use("Agg")  # headless: render to file, never open a window
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_curve,
    auc,
)

from config.settings import REPORTS_DIR


class ReportGenerator:
    """
    Turn a single evaluation run into thesis-ready artifacts:

        reports/metrics.json         — all scalar metrics + confusion matrix
        reports/confusion_matrix.png — 2x2 labelled heatmap
        reports/roc_curve.png        — ROC curve with AUC

    y_true  : ground-truth labels (0 normal, 1 anomaly)
    y_pred  : predicted labels (0/1)
    y_score : continuous anomaly score (higher = more anomalous); needed
              for the ROC curve. Optional — ROC is skipped without it.
    """

    def __init__(self, output_dir=REPORTS_DIR):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, y_true, y_pred, y_score=None):

        y_true = list(y_true)
        y_pred = list(y_pred)

        metrics = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "support": {
                "total": len(y_true),
                "normal": sum(1 for v in y_true if v == 0),
                "anomaly": sum(1 for v in y_true if v == 1),
            },
            "accuracy": round(accuracy_score(y_true, y_pred), 4),
            "precision": round(
                precision_score(y_true, y_pred, zero_division=0), 4
            ),
            "recall": round(
                recall_score(y_true, y_pred, zero_division=0), 4
            ),
            "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        }

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        metrics["confusion_matrix"] = {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        }

        self._plot_confusion_matrix(cm)

        roc_auc = None
        if y_score is not None:
            roc_auc = self._plot_roc_curve(y_true, list(y_score))
            if roc_auc is not None:
                metrics["roc_auc"] = round(roc_auc, 4)

        metrics_path = os.path.join(self.output_dir, "metrics.json")
        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=4)

        print(f"\nReport artifacts written to {self.output_dir}/")
        print(f"  metrics.json, confusion_matrix.png"
              + (", roc_curve.png" if roc_auc is not None else ""))

        return metrics

    # ------------------------------------------------------------------
    # Charts
    # ------------------------------------------------------------------

    def _plot_confusion_matrix(self, cm):

        labels = ["NORMAL", "ANOMALY"]

        fig, ax = plt.subplots(figsize=(4.5, 4))
        im = ax.imshow(cm, cmap="Blues")

        ax.set_xticks([0, 1], labels=labels)
        ax.set_yticks([0, 1], labels=labels)
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        ax.set_title("Confusion Matrix")

        threshold = cm.max() / 2 if cm.max() else 0
        for i in range(2):
            for j in range(2):
                ax.text(
                    j, i, str(cm[i, j]),
                    ha="center", va="center",
                    color="white" if cm[i, j] > threshold else "black",
                    fontsize=14, fontweight="bold",
                )

        fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        fig.tight_layout()

        path = os.path.join(self.output_dir, "confusion_matrix.png")
        fig.savefig(path, dpi=120)
        plt.close(fig)

    def _plot_roc_curve(self, y_true, y_score):

        # ROC needs both classes present to be meaningful.
        if len(set(y_true)) < 2:
            print("ROC skipped: evaluation set has a single class.")
            return None

        fpr, tpr, _ = roc_curve(y_true, y_score, pos_label=1)
        roc_auc = auc(fpr, tpr)

        fig, ax = plt.subplots(figsize=(5, 4))
        ax.plot(fpr, tpr, color="#1f77b4", lw=2,
                label=f"ROC (AUC = {roc_auc:.3f})")
        ax.plot([0, 1], [0, 1], color="gray", lw=1, linestyle="--",
                label="Chance")

        ax.set_xlim(-0.02, 1.0)
        ax.set_ylim(0.0, 1.02)
        ax.set_xlabel("False Positive Rate")
        ax.set_ylabel("True Positive Rate")
        ax.set_title("ROC Curve — Isolation Forest")
        ax.legend(loc="lower right")
        fig.tight_layout()

        path = os.path.join(self.output_dir, "roc_curve.png")
        fig.savefig(path, dpi=120)
        plt.close(fig)

        return roc_auc
