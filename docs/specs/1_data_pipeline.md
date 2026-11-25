# Spec · Data & feature pipeline

**Owner:** Habiba · **Tasks:** H-1 to H-7 · **Slides:** 8–11

> ALL-4 draft. Pre-filled from the proposal deck; replace every _TODO_ with what you actually built.

## Purpose
Turn AIT Netflow records into the feature table in `docs/contracts/feature_contract.md`. The same code runs during training and when logs are replayed, so the model always sees data in the same format.

## Inputs
- AIT Netflow Data Set, 8 networks (doi 10.5281/zenodo.13168643)
- `label_info.txt` (which labels are normal and which are attacks)

## Steps
1. Load flows for one network and map AIT columns to contract names (mapping table in `docs/contracts/feature_contract.md`).
2. Compute flow features.
3. Compute past-only 5-minute window features per `src_ip`.
4. Apply the labeling rule (H-3): exact, protocol-aware match against `label_info.txt` (13 normal + 39 attack TCP labels, 12 normal + 1 attack UDP label). Empty or unknown labels are left out, never counted as normal. Full rule: `docs/data/H3_labeling_rule.md`.
5. Keep `src_ip` and `dst_ip`; add the encoded IP columns while `USE_IP_AS_MODEL_INPUT` is on.
6. Split by network: train = _TODO_, validation = _TODO_, test = _TODO_.

## Guarantees (each one has a test)
- No window looks into the future: `test_removing_the_future_changes_nothing`, `test_changing_the_future_changes_nothing`, `test_window_boundaries`, `test_ties_do_not_see_each_other` (tests/test_h4_features.py), plus a check on the real data in every `scripts/build_features.py` run
- Every split contains attack flows: _TODO test name_
- No network appears in two splits: _TODO test name_
- Output passes `validate_feature_frame()`: `test_output_follows_the_team_contract`, and every `scripts/build_features.py` run
- Same code for training and runtime: `test_runtime_equals_batch`

## Results to report
| Network | Flows | Attack flows | Split |
|---|---:|---:|---|
| fox | 351,908 | 71,173 | |
| harrison | 437,659 | 100,352 | |
| russellmitchell | 377,704 | 171,028 | |
| santos | 288,547 | 18,785 | |
| shaw | 453,541 (942 unlabeled, left out) | 63,255 | |
| wardbeck | 390,224 | 20,175 | |
| wheeler | 536,206 | 112,570 | |
| wilson | 629,553 | 61,540 | |

Counts from H-1 (24 Nov 2026). Split: H-6, to do.

## Limits
Simulated network. Password cracking and privilege escalation may not show in flows. IPs differ per network (see the IP decision in the feature contract).
