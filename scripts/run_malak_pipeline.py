
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinelai.detection.data import load_feature_table
from sentinelai.detection.training import (
    split_by_network,
    tune_random_forest,
    fit_final_model,
    evaluate_test_once,
    repeated_validation_runs,
    save_model_bundle,
    evaluate_rules_baseline,
)
from sentinelai.detection.rules import apply_rules
from sentinelai.detection.agent import DetectionAgent
from sentinelai.platform.shared_memory import SharedMemory
from sentinelai.detection.evaluation import evaluate_predictions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--data",
        required=True,
        help="Team-contract feature file (.csv or .parquet)",
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "outputs"),
    )
    parser.add_argument(
        "--policy",
        choices=["or", "and"],
        default="or",
    )

    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # M1: Load and validate the shared feature contract.
    df = load_feature_table(args.data)
    split = split_by_network(df)

    print(
        f"Split: {split.mode}; "
        f"train={len(split.train)}, "
        f"validation={len(split.validation)}, "
        f"test={len(split.test)}"
    )

    if split.mode.startswith("DEVELOPMENT_ONLY"):
        print(
            "WARNING: one-network row split is for pipeline "
            "debugging only, not final evaluation."
        )

    # M2: Apply explainable detection rules.
    hits = apply_rules(df)

    rule_table = df[["flow_id", "network"]].copy()
    rule_table["rule_hits"] = [";".join(x) for x in hits]

    rule_table.to_csv(
        output_dir / "m2_rule_hits.csv",
        index=False,
    )

    # M3: Tune the Random Forest using validation data.
    params, tuning = tune_random_forest(split)

    tuning.to_csv(
        output_dir / "m3_validation_tuning.csv",
        index=False,
    )

    (output_dir / "m3_selected_parameters.json").write_text(
        json.dumps(params, indent=2)
    )

    # M4: Repeated validation, final training, and test evaluation.
    repeated_validation_runs(
        split, params
    ).to_csv(
        output_dir / "m4_repeated_validation_runs.csv",
        index=False,
    )

    model, cols = fit_final_model(split, params)

    model_path = output_dir / "malak_random_forest.joblib"

    save_model_bundle(model, params, model_path)

    rf_metrics, rf_prob, rf_pred = evaluate_test_once(
        model,
        split,
        params["threshold"],
    )

    pd.DataFrame({
        "feature": cols,
        "importance": model.feature_importances_,
    }).sort_values(
        "importance",
        ascending=False,
    ).to_csv(
        output_dir / "m4_feature_importance.csv",
        index=False,
    )

    # M6: Compare rules, RF, and hybrid on the same test rows.
    rules_metrics, test_hits, rules_pred = (
        evaluate_rules_baseline(split)
    )

    hybrid_pred = np.logical_or(
        rules_pred,
        rf_pred,
    ).astype(int)

    hybrid_metrics = evaluate_predictions(
        split.test["label"],
        hybrid_pred,
    )

    comparison = pd.DataFrame([
        {"approach": "Rules-only", **rules_metrics},
        {"approach": "RF-only", **rf_metrics},
        {"approach": "Hybrid (RF OR rules)", **hybrid_metrics},
    ])

    comparison.to_csv(
        output_dir / "m6_three_way_comparison.csv",
        index=False,
    )

    # M5: Runtime agent receives test rows without ground-truth labels.
    # Use a separate demo database, not the team's production database.
    memory = SharedMemory(
        str(output_dir / "sentinelai_shared_memory.db")
    )

    agent = DetectionAgent(
        model_path,
        memory,
        decision_policy=args.policy,
    )

    runtime = split.test.drop(
        columns=["label", "label_raw"],
        errors="ignore",
    ).copy()

    alerts = agent.run(runtime)

    (output_dir / "m5_alerts.json").write_text(
        json.dumps(
            alerts,
            indent=2,
            ensure_ascii=False,
        )
    )

    # Save the complete run summary.
    summary = {
        "input_file": str(Path(args.data).resolve()),
        "split_mode": split.mode,
        "split_networks": {
            key: sorted(
                frame.network.astype(str).unique().tolist()
            )
            for key, frame in [
                ("train", split.train),
                ("validation", split.validation),
                ("test", split.test),
            ]
        },
        "split_rows": {
            "train": len(split.train),
            "validation": len(split.validation),
            "test": len(split.test),
        },
        "selected_validation_parameters": params,
        "test_metrics": {
            "rules_only": rules_metrics,
            "rf_only": rf_metrics,
            "hybrid_or": hybrid_metrics,
        },
        "alerts_written": len(alerts),
        "model_file": str(model_path.resolve()),
        "important_warning": (
            "DEVELOPMENT ONLY: a row split within one network "
            "is not a final unseen-network evaluation."
            if split.mode.startswith("DEVELOPMENT_ONLY")
            else
            "Confirm H-6 provenance and split assignments "
            "before presenting."
        ),
    }

    (output_dir / "m1_m6_summary.json").write_text(
        json.dumps(summary, indent=2)
    )

    print("\nM-6 comparison on the same held-out test rows:")

    print(
        comparison[
            [
                "approach",
                "precision",
                "recall",
                "f1",
                "false_positive_rate",
                "tn",
                "fp",
                "fn",
                "tp",
            ]
        ].to_string(index=False)
    )

    print(f"\nAlerts generated: {len(alerts)}")
    print(f"Model saved: {model_path.resolve()}")
    print(f"Outputs: {output_dir.resolve()}")


if __name__ == "__main__":
    main()
