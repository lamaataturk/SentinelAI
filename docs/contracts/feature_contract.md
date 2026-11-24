# ALL-1 (a) · Feature table contract

**Owner of the producing code:** Habiba (H-4) · **Main reader:** Malak (M-1, M-3, M-5)
**Code:** `sentinelai/contracts/features.py` · **Example:** `fixtures/features_sample.csv`

One row = one network flow. Every file that goes from the feature module to the model must have these columns, with these names and types.

## Context columns (always kept)

| Column | Type | Notes |
|---|---|---|
| `flow_id` | str | Unique, e.g. `f-000123`. Alerts cite it as `flow:f-000123`. |
| `network` | str | AIT network name (fox, harrison, …). Used for the split by network. |
| `start_time`, `end_time` | str | ISO 8601 UTC ending in `Z`. |
| `src_ip`, `dst_ip` | str | **Kept.** Never dropped from the table, alerts or incidents. |
| `src_port` | int | |

## Model inputs

| Column | Type | Meaning |
|---|---|---|
| `duration_s` | float | Flow duration in seconds |
| `bytes`, `packets` | int | Size of the flow |
| `bytes_per_packet` | float | 0 when `packets` is 0 |
| `dst_port` | int | 0–65535 |
| `protocol` | int | 6 = TCP, 17 = UDP |
| `win5_conn_count` | int | Connections from `src_ip` in the 5 minutes **before** this flow |
| `win5_distinct_dst_ports` | int | Different ports contacted (scans) |
| `win5_distinct_dst_hosts` | int | Different hosts contacted |
| `win5_dns_count` | int | DNS flows from `src_ip` |
| `win5_dns_avg_bytes` | float | Mean size of those DNS flows (data theft over DNS) |
| `src_ip_int`, `dst_ip_int`, `src_is_private`, `dst_is_private` | int | IPs encoded as numbers by `add_ip_model_features()`. Used while `USE_IP_AS_MODEL_INPUT = True`. |

## Labels (training and evaluation only)

| Column | Type | Notes |
|---|---|---|
| `label_raw` | str | AIT's own label (`service_scan`, `mail`, …) |
| `label` | int | 0 = normal, 1 = suspicious, from the rule in H-3 |

No agent reads `label` or `label_raw` at runtime.

## Decision on IP addresses

The team decided on 23 Nov 2026 that IP addresses stay in the data. That decision has two parts:

1. **In the data and messages:** IPs are always present. Investigation links alerts by host, and the reports name the hosts involved.
2. **As model inputs:** `USE_IP_AS_MODEL_INPUT = True` for now. Slides 10, 11 and 17 currently say IPs are *not* used as features, because each AIT network has its own addresses. Before the presentation, either update those slides, or run M-4 both ways (flag on/off) and report both. The split by network will show whether the model learned addresses instead of behaviour.

## Still to confirm (H-1)

- How each AIT Netflow column maps to the names above. Fill in the table below once the CSVs are opened.

| Our column | AIT column | Checked by |
|---|---|---|
| `start_time` | _to confirm_ | |
| `src_ip` | _to confirm_ | |
| `dst_ip` | _to confirm_ | |
| `bytes` | _to confirm_ | |
| `packets` | _to confirm_ | |
| … | | |

## Changing this contract

Open a pull request that changes `features.py` and this page together, and tag all five people. `pytest` must still pass.
