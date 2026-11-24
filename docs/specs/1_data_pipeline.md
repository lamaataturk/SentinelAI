# Spec · Data & feature pipeline

**Owner:** Habiba · **Tasks:** H-1 to H-7 · **Slides:** 8–11

> ALL-4 draft. Pre-filled from the proposal deck; replace every _TODO_ with what you actually built.

## Purpose
Turn AIT Netflow records into the feature table in `docs/contracts/feature_contract.md`. The same code runs during training and when logs are replayed, so the model always sees data in the same format.

## Inputs
- AIT Netflow Data Set, 8 networks (doi 10.5281/zenodo.13168643)
- `label_info.txt` (which labels are normal and which are attacks)

## Steps
1. Load flows for one network and map AIT columns to contract names (mapping table: _TODO after H-1_).
2. Compute flow features.
3. Compute past-only 5-minute window features per `src_ip`.
4. Apply the labeling rule (H-3): _TODO: paste the final list of normal labels and attack labels_.
5. Keep `src_ip` and `dst_ip`; add the encoded IP columns while `USE_IP_AS_MODEL_INPUT` is on.
6. Split by network: train = _TODO_, validation = _TODO_, test = _TODO_.

## Guarantees (each one has a test)
- No window looks into the future: _TODO test name_
- Every split contains attack flows: _TODO test name_
- No network appears in two splits: _TODO test name_
- Output passes `validate_feature_frame()`

## Results to report
| Network | Flows | Attack flows | Split |
|---|---|---|---|
| fox | _TODO_ | _TODO_ | |
| harrison | | | |
| russellmitchell | | | |
| santos | | | |
| shaw | | | |
| wardbeck | | | |
| wheeler | | | |
| wilson | | | |

## Limits
Simulated network. Password cracking and privilege escalation may not show in flows. IPs differ per network (see the IP decision in the feature contract).
