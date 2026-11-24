# Spec · Detection Agent (ML + rules)

**Owner:** Malak · **Tasks:** M-1 to M-6 · **Slides:** 12, 13, 17

> ALL-4 draft. Pre-filled from the proposal deck; replace every _TODO_ with what you actually built.

| | |
|---|---|
| **Goal** | Spot suspicious network activity and back every alert with evidence |
| **Observes** | Rows of the feature table (one flow plus its 5-minute window) |
| **State** | Loaded model, threshold, rule set, IDs of flows already alerted on |
| **Decision policy** | Hybrid: alert if `rf_score ≥ threshold` **or** a rule fires; when both agree, `detector = "hybrid"` (stronger evidence). _TODO: final threshold and how scores combine_ |
| **Actions** | Writes `Alert` messages (score, rule hits, flow IDs, IPs) to shared memory |
| **Reads** | Feature rows |
| **Writes** | `Alert` |
| **Autonomy limit** | Never blocks traffic; the model never retrains at runtime |

## Model
- `RandomForestClassifier`, `class_weight = "balanced"`, seed _TODO_
- Tuned on validation networks only: max_depth _TODO_, min_samples_leaf _TODO_, threshold _TODO_
- Inputs: `model_input_columns()` (includes encoded IPs while the flag is on)
- Saved with joblib to _TODO path_

## Rules
| Rule ID | Fires when | Targets |
|---|---|---|
| `R-MANY-PORTS-5MIN` | `win5_distinct_dst_ports` ≥ _TODO_ | scans |
| `R-DNS-VOLUME-HIGH` | `win5_dns_count` ≥ _TODO_ | DNS exfiltration |
| `R-DNS-LARGE-QUERY` | `win5_dns_avg_bytes` ≥ _TODO_ | DNS exfiltration |
| _TODO_ | | |

## Evaluation (slide 17)
| Metric | Rules-only | RF-only | Hybrid |
|---|---|---|---|
| Precision | | | |
| Recall | | | |
| F1 | | | |
| False-positive rate | | | |

If IPs are used as model inputs, also report RF-only with `USE_IP_AS_MODEL_INPUT = False`.

## Tests
_TODO: list test names (threshold boundary, rule boundary, every alert cites a flow)_
