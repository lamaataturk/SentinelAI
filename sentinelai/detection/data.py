
"""Data loading and validation for the SentinelAI detection pipeline.

Uses the shared team feature contract as the single source of truth.
Original source columns are validated before generated IP features are added.
"""

from pathlib import Path

import numpy as np
import pandas as pd

from sentinelai.contracts.features import (
    ALL_COLUMNS,
    ID_COLUMNS,
    FLOW_FEATURES,
    WINDOW_FEATURES,
    IP_MODEL_FEATURES,
    LABEL_COLUMNS,
    USE_IP_AS_MODEL_INPUT,
    model_input_columns,
    add_ip_model_features,
    validate_feature_frame,
)


# Shared aliases used by other detection modules.
FEATURE_COLUMNS = model_input_columns()
REQUIRED_COLUMNS = ALL_COLUMNS
TARGET_COLUMN = "label"


def validate_feature_table(df: pd.DataFrame) -> list[str]:
    """Validate the original feature table against the shared contract."""
    if not isinstance(df, pd.DataFrame):
        return ["Input must be a pandas DataFrame."]

    return validate_feature_frame(df)


def load_feature_table(path: str | Path) -> pd.DataFrame:
    """Load, validate, and prepare a CSV or Parquet feature table."""

    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Feature file not found: {path}")

    suffix = path.suffix.lower()

    if suffix == ".csv":
        df = pd.read_csv(path)
    elif suffix in {".parquet", ".pq"}:
        df = pd.read_parquet(path)
    else:
        raise ValueError(
            f"Unsupported file format: {suffix}. "
            "Use CSV or Parquet."
        )

    # Step 1: Validate the original source data.
    errors = validate_feature_table(df)

    if errors:
        raise ValueError(
            "Feature contract validation failed:\n- "
            + "\n- ".join(errors)
        )

    # Step 2: Generate IP model features.
    # These four columns are not expected in the original CSV.
    prepared = add_ip_model_features(df.copy())

    # Step 3: Verify that all model inputs now exist.
    expected_features = model_input_columns()

    missing = [
        column
        for column in expected_features
        if column not in prepared.columns
    ]

    if missing:
        raise ValueError(
            "Missing generated model inputs: "
            + ", ".join(missing)
        )

    # Step 4: Check model inputs are numeric and finite.
    for column in expected_features:
        prepared[column] = pd.to_numeric(
            prepared[column],
            errors="coerce"
        )

        values = prepared[column].to_numpy(dtype=float)

        if not np.isfinite(values).all():
            raise ValueError(
                f"Model input '{column}' contains missing, "
                "non-numeric, or non-finite values."
            )

    return prepared


def load_feature_csv(path: str | Path) -> pd.DataFrame:
    """Backward-compatible CSV loader."""
    return load_feature_table(path)


def get_model_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return only the agreed model input columns."""

    columns = model_input_columns()

    missing = [
        column for column in columns
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            "Missing model input columns: "
            + ", ".join(missing)
        )

    return df.loc[:, columns].copy()


def get_labels(df: pd.DataFrame) -> pd.Series:
    """Return the agreed binary target column."""

    if TARGET_COLUMN not in df.columns:
        raise ValueError(
            f"Missing target column: {TARGET_COLUMN}"
        )

    return df[TARGET_COLUMN].astype(int).copy()
