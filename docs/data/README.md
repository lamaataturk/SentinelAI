# Data pipeline (Habiba, H-1 to H-5): where everything is

Run everything from the repo root. Data is never committed: `data/raw/` and `data/processed/` are git-ignored.

**Where the AIT files go:** put the 8 `<network>_netflows.zip` files and `label_info.txt` (Zenodo record 13168643) in `data/raw/ait/downloads/`. The H-1 scripts read `<--data-dir>/downloads/`, so `build_features.py` needs `--data-dir data/raw/ait/downloads` to read the same files.

## Reports (read these first)

| File | Task | What it is |
|---|---|---|
| [H1_AIT_verification_report.md](H1_AIT_verification_report.md) | H-1 | AIT Netflow check: checksums, columns, labels, attack counts per network. Decision: **GO with conditions**. Full generated report; its evidence files are in [h1_evidence/](h1_evidence/). |
| [H2_IDS2018_backup_report.md](H2_IDS2018_backup_report.md) | H-2 | CSE-CIC-IDS2018 backup check: size, format, labels, how to switch. Decision: **suitable with conditions**. Exact copy of the generated report. |
| [H3_labeling_rule.md](H3_labeling_rule.md) | H-3 | The labeling rule (AIT label → 0 normal / 1 suspicious), for sign-off. |

## Scripts

| File | Task | How to run |
|---|---|---|
| [scripts/h1_verify_ait.py](../../scripts/h1_verify_ait.py) | H-1 | `python scripts/h1_verify_ait.py`. Checks the AIT archives against Zenodo and writes evidence files to `data/processed/h1_outputs/`. Needs internet (Zenodo API) and `requests`. |
| [scripts/h1_make_report.py](../../scripts/h1_make_report.py) | H-1 | `python scripts/h1_make_report.py`. Builds `H1_AIT_Verification_Report.md` from the H-1 evidence files. |
| [scripts/h2_check_ids2018.py](../../scripts/h2_check_ids2018.py) | H-2 | `python scripts/h2_check_ids2018.py`. Streams the CSE-CIC-IDS2018 CSVs from the public S3 bucket and writes evidence to `data/processed/h2_outputs/`. Needs internet and `requests`. |
| [scripts/h2_make_report.py](../../scripts/h2_make_report.py) | H-2 | `python scripts/h2_make_report.py`. Builds the H-2 report from the H-2 evidence plus the H-1 outputs (for the AIT comparison). |
| [scripts/build_features.py](../../scripts/build_features.py) | H-5 | `python scripts/build_features.py --data-dir data/raw/ait/downloads --networks fox` (or `all`). Writes `data/processed/features_<network>.csv.gz` in the team contract format. |

The H-1/H-2 scripts are copied exactly from the Colab notebook. Only the default paths changed, to the `data/` folders above. Their notebook names were `h1_ait_verify.py` and `h2_ids2018_scan.py`; the reports still use those names.

## Code and tests

| File | Task | What it is |
|---|---|---|
| [sentinelai/data/labeling.py](../../sentinelai/data/labeling.py) | H-3 | The labeling rule in code. |
| [sentinelai/data/features.py](../../sentinelai/data/features.py) | H-4 | AIT Netflow rows → the ALL-1 feature table, with past-only 5-minute windows. |
| [tests/test_h3_labeling.py](../../tests/test_h3_labeling.py), [tests/test_h4_features.py](../../tests/test_h4_features.py) | H-3, H-4 | Run with `pytest`. Helpers: [tests/ait_testdata.py](../../tests/ait_testdata.py). |

## Other

| File | What it is |
|---|---|
| [docs/contracts/feature_contract.md](../contracts/feature_contract.md) | Section "AIT Netflow → contract mapping": which AIT column becomes which contract column. |
| [docs/specs/1_data_pipeline.md](../specs/1_data_pipeline.md) | Data pipeline spec, with flow and attack counts per network. |
| [notebooks/habiba_data_pipeline_h1_h5.ipynb](../../notebooks/habiba_data_pipeline_h1_h5.ipynb) | The Colab notebook where H-1 to H-5 were done. Its H-3 to H-5 cells are the first draft; the team version is `sentinelai/data/` + `scripts/build_features.py`. |

## Evidence files

| Folder | What it is |
|---|---|
| [h1_evidence/](h1_evidence/) | The CSV/JSON files behind the H-1 report, from the run on 2026-11-25: `archive_checksums.csv`, `csv_file_quality_report.csv`, `label_counts_by_file.csv`, `ait_network_attack_counts.csv`, `label_mapping.json`, `run_manifest.json`. `scripts/h1_verify_ait.py` regenerates them in `data/processed/h1_outputs/`. |

The H-2 evidence files are not in the repo yet; `scripts/h2_check_ids2018.py` regenerates them in `data/processed/h2_outputs/`.
