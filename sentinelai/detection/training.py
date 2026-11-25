
"""M-1/M-3/M-4: data splitting, model tuning, validation and evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from sentinelai.detection.data import (
    FEATURE_COLUMNS,
    get_model_features,
    get_labels,
    load_feature_table,
)
from sentinelai.detection.evaluation import (
    evaluate_predictions,
    choose_threshold,
)
from sentinelai.detection.rules import apply_rules


SEED = 42
TARGET_COLUMN = "label"


@dataclass
class DataSplit:
    train: pd.DataFrame
    validation: pd.DataFrame
    test: pd.DataFrame
    mode: str


def _get_target(df: pd.DataFrame) -> pd.Series:
    """Use the agreed label column, with y fallback for legacy test data."""

    if TARGET_COLUMN in df.columns:
        return df[TARGET_COLUMN].astype(int)

    if "y" in df.columns:
        return df["y"].astype(int)

    raise ValueError("Dataset must contain a 'label' target column.")


def _validate_split_input(df: pd.DataFrame) -> pd.Series:
    """Validate the fields needed for splitting without enforcing model schema."""

    if not isinstance(df, pd.DataFrame):
        raise TypeError("Input must be a pandas DataFrame.")

    if "network" not in df.columns:
        raise ValueError("Dataset must contain a 'network' column.")

    if df.empty:
        raise ValueError("Dataset is empty.")

    target = _get_target(df)

    if target.isna().any():
        raise ValueError("Target column contains missing values.")

    if not set(target.unique()).issubset({0, 1}):
        raise ValueError("Target column must contain only 0 and 1.")

    return target


def _check_partition(name: str, part: pd.DataFrame) -> None:
    """Ensure each partition contains both target classes."""

    if part.empty:
        raise ValueError(f"{name} split is empty.")

    target = _get_target(part)

    if target.nunique() < 2:
        raise ValueError(
            f"{name} split must contain both labels 0 and 1; "
            f"found {target.value_counts().to_dict()}"
        )


def split_by_network(
    df: pd.DataFrame,
    seed: int = SEED,
    allow_development_row_split: bool = True,
) -> DataSplit:
    """Create train, validation and test partitions.

    Three or more networks:
        Hold out separate networks for validation and test.

    One network:
        Use a stratified row split for development only.
        This is not a final unseen-network evaluation.

    A supplied split column:
        Honor train/validation/test assignments only when networks
        are disjoint between all three partitions.
    """

    target = _validate_split_input(df)

    if "split" in df.columns:
        split_values = df["split"].astype(str).str.lower()

        required_splits = {"train", "validation", "test"}

        if set(split_values.unique()) != required_splits:
            raise ValueError(
                "Provided split column must contain exactly "
                "train, validation and test."
            )

        parts = {
            name: df[split_values == name].copy()
            for name in ("train", "validation", "test")
        }

        networks = {
            name: set(part["network"].astype(str))
            for name, part in parts.items()
        }

        comparisons = [
            ("train", "validation"),
            ("train", "test"),
            ("validation", "test"),
        ]

        for first, second in comparisons:
            overlap = networks[first] & networks[second]

            if overlap:
                raise ValueError(
                    "Network leakage: networks occur in both "
                    f"{first} and {second}: {sorted(overlap)}"
                )

        mode = "provided_network_split"

    else:
        unique_networks = sorted(df["network"].astype(str).unique())

        if len(unique_networks) >= 3:
            rng = np.random.RandomState(seed)

            shuffled = list(
                np.array(unique_networks)[
                    rng.permutation(len(unique_networks))
                ]
            )

            n_test = max(1, round(0.20 * len(shuffled)))
            n_validation = max(1, round(0.20 * len(shuffled)))

            test_networks = set(shuffled[:n_test])
            validation_networks = set(
                shuffled[n_test:n_test + n_validation]
            )

            train_networks = set(shuffled) - (
                test_networks | validation_networks
            )

            parts = {
                "train": df[
                    df["network"].astype(str).isin(train_networks)
                ].copy(),
                "validation": df[
                    df["network"].astype(str).isin(validation_networks)
                ].copy(),
                "test": df[
                    df["network"].astype(str).isin(test_networks)
                ].copy(),
            }

            mode = "automatic_network_holdout"

        elif len(unique_networks) == 1 and allow_development_row_split:
            # Development-only fallback. This does not measure
            # generalization to unseen networks.
            try:
                train_df, remaining_df = train_test_split(
                    df,
                    test_size=0.40,
                    random_state=seed,
                    stratify=target,
                )

                remaining_target = _get_target(remaining_df)

                validation_df, test_df = train_test_split(
                    remaining_df,
                    test_size=0.50,
                    random_state=seed,
                    stratify=remaining_target,
                )

            except ValueError as exc:
                raise ValueError(
                    "Not enough examples per class for a stratified "
                    "development split. More labelled data is required."
                ) from exc

            parts = {
                "train": train_df.copy(),
                "validation": validation_df.copy(),
                "test": test_df.copy(),
            }

            mode = "DEVELOPMENT_ONLY_ROW_SPLIT_NOT_FINAL_H6"

        else:
            raise ValueError(
                "Final evaluation requires at least 3 distinct networks "
                "or a valid network-disjoint train/validation/test split."
            )

    for name, part in parts.items():
        _check_partition(name, part)

    return DataSplit(
        train=parts["train"],
        validation=parts["validation"],
        test=parts["test"],
        mode=mode,
    )


def _xy(df: pd.DataFrame):
    """Prepare model inputs and target using the shared feature contract."""

    X = get_model_features(df)
    y = get_labels(df) if TARGET_COLUMN in df.columns else _get_target(df)

    return X.astype(float), y.astype(int)


def _positive_class_probabilities(model, X):
    """Return probabilities for class 1, regardless of class ordering."""

    if 1 not in model.classes_:
        raise ValueError("Trained model does not contain positive class 1.")

    positive_index = list(model.classes_).index(1)

    return model.predict_proba(X)[:, positive_index]


def tune_random_forest(split: DataSplit, seed: int = SEED):
    """Tune hyperparameters using training and validation only.

    The test partition is not accessed during tuning.
    """

    X_train, y_train = _xy(split.train)
    X_validation, y_validation = _xy(split.validation)

    rows = []
    best = None

    for depth in (8, 16, None):
        for leaf in (1, 3, 5):
            model = RandomForestClassifier(
                n_estimators=250,
                class_weight="balanced",
                max_depth=depth,
                min_samples_leaf=leaf,
                random_state=seed,
                n_jobs=-1,
            )

            model.fit(X_train, y_train)

            probabilities = _positive_class_probabilities(
                model, X_validation
            )

            threshold, metrics = choose_threshold(
                y_validation,
                probabilities,
            )

            for metric in metrics:
                rows.append({
                    "max_depth": depth,
                    "min_samples_leaf": leaf,
                    **metric,
                })

            top = metrics[0]

            key = (
                top["f1"],
                top["precision"],
                top["threshold"],
            )

            if best is None or key > best[0]:
                best = (
                    key,
                    {
                        "max_depth": depth,
                        "min_samples_leaf": leaf,
                        "threshold": float(threshold),
                    },
                )

    if best is None:
        raise RuntimeError("Random Forest tuning did not produce a result.")

    results = pd.DataFrame(rows).sort_values(
        ["f1", "precision"],
        ascending=False,
    ).reset_index(drop=True)

    return best[1], results


def fit_final_model(
    split: DataSplit,
    params: dict,
    seed: int = SEED,
):
    """Fit the final model using train plus validation data."""

    train_validation = pd.concat(
        [split.train, split.validation],
        ignore_index=True,
    )

    X, y = _xy(train_validation)

    model = RandomForestClassifier(
        n_estimators=250,
        class_weight="balanced",
        max_depth=params["max_depth"],
        min_samples_leaf=int(params["min_samples_leaf"]),
        random_state=seed,
        n_jobs=-1,
    )

    model.fit(X, y)

    return model, list(FEATURE_COLUMNS)


def evaluate_test_once(
    model,
    split: DataSplit,
    threshold: float,
):
    """Evaluate the final model on the untouched test partition once."""

    X_test, y_test = _xy(split.test)

    probabilities = _positive_class_probabilities(model, X_test)

    predictions = (
        probabilities >= float(threshold)
    ).astype(int)

    metrics = evaluate_predictions(y_test, predictions)

    return metrics, probabilities, predictions


def repeated_validation_runs(
    split: DataSplit,
    params: dict,
    seeds=(42, 43, 44),
):
    """Check validation stability across multiple random seeds."""

    X_train, y_train = _xy(split.train)
    X_validation, y_validation = _xy(split.validation)

    rows = []

    for seed in seeds:
        model = RandomForestClassifier(
            n_estimators=250,
            class_weight="balanced",
            max_depth=params["max_depth"],
            min_samples_leaf=int(params["min_samples_leaf"]),
            random_state=seed,
            n_jobs=-1,
        )

        model.fit(X_train, y_train)

        probabilities = _positive_class_probabilities(
            model, X_validation
        )

        predictions = (
            probabilities >= float(params["threshold"])
        ).astype(int)

        rows.append({
            "seed": seed,
            **evaluate_predictions(y_validation, predictions),
        })

    return pd.DataFrame(rows)


def save_model_bundle(
    model,
    params: dict,
    path: str | Path,
):
    """Save the trained model and its feature contract metadata."""

    bundle = {
        "model": model,
        "threshold": float(params["threshold"]),
        "feature_columns": list(FEATURE_COLUMNS),
        "seed": SEED,
        "model_version": "sentinelai-team-contract-rf-1.0",
        "feature_source": "sentinelai.contracts.features",
        "target_column": TARGET_COLUMN,
        "use_ip_as_model_input": True,
    }

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(bundle, output_path)

    return bundle


def evaluate_rules_baseline(split: DataSplit):
    """Evaluate the rules-only baseline on the test partition."""

    hits = apply_rules(split.test)

    predictions = np.array(
        [bool(hit) for hit in hits],
        dtype=int,
    )

    target = _get_target(split.test)

    metrics = evaluate_predictions(target, predictions)

    return metrics, hits, predictions
