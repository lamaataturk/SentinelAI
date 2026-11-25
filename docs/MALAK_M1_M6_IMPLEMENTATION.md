# Malak M-1 to M-6 implementation

## Data source and contract boundary
This implementation consumes Habiba's H-4/H-5 feature table (28 model inputs, `y`, `flow_id`, `network`, `event_end_ms`, `src_ip`, `dst_ip`). It uses the exact feature names from her notebook. It does **not** rename those features into Lama's different proposed feature contract because their meanings and units are not equivalent. Lama's `messages.py` and SQLite `SharedMemory` are left unchanged; M-5 publishes Alerts through that message contract.

H-4 output columns do not contain client source port or flow start time. The Alert contract requires a `src_port` key, so this implementation sends `null`; it uses the available flow end timestamp for both `first_seen` and `last_seen`. These limitations are explicit rather than fabricated.

## Run in Windows / VS Code

```powershell
cd C:\Users\Compumarts\Documents\SentinelAI
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
```

Place Habiba's generated `features_fox.parquet` in `h5_outputs` (or use its actual location), then run a development smoke test:

```powershell
python scripts\run_malak_pipeline.py --data h5_outputs\features_fox.parquet
```

**Important:** Fox is one network only. The code deliberately labels a one-network row split `DEVELOPMENT_ONLY_ROW_SPLIT_NOT_FINAL_H6`. Do not report those metrics as final. For final M-3/M-4/M-6, provide Habiba's H-6 network-disjoint dataset/split with train, validation and test networks separated, or a combined feature table containing at least three networks. The script checks for network leakage and both classes in every partition.

## M-1 to M-6 outputs
- M-1: `m1_m6_summary.json` includes split metadata and metrics.
- M-2: `m2_rule_hits.csv` maps each flow ID to matching rule names.
- M-3: `m3_validation_tuning.csv`, `m3_selected_parameters.json`.
- M-4: `m4_repeated_validation_runs.csv`, `m4_feature_importance.csv`, `malak_random_forest.joblib`.
- M-5: `m5_alerts.json`, `sentinelai_shared_memory.db`.
- M-6: `m6_three_way_comparison.csv` compares rules-only, RF-only and hybrid on the same test rows.

## Rule thresholds
M-2 uses transparent initial thresholds in `sentinelai/detection/rules.py`. They are starting values, not empirically tuned claims. The RF threshold and hyperparameters are selected on validation data only. The test set is evaluated once.
