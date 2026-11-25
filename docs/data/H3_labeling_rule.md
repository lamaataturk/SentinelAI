# H-3 Labeling rule: AIT Netflow labels → normal (0) / suspicious (1)

**Rule version:** 1.0 · **Code:** `sentinelai/data/labeling.py` · **Tests:** `tests/test_h3_labeling.py`
**Owner:** Habiba · **Checked by:** Malak (sign-off below)

## The rule

1. The only source of truth is the publisher's `label_info.txt` (Zenodo record 13168643,
   MD5 `e32c0e08d15725999df0c6a0c02aff47`; the code refuses any other copy).
2. **label = 0 (normal)** if the flow's label is listed under *Benign labels in &lt;its protocol&gt;*.
   **label = 1 (suspicious)** if it is listed under *Malicious labels in &lt;its protocol&gt;*.
3. Matching is **exact**: no trimming of spaces, no lower/upper-case changes, and the protocol must
   match. For example, `data exfiltration` is a UDP label, so it would not be mapped if it showed up in a TCP file.
4. Everything else is **unmapped (label = NA)**: an empty label, an unknown string, or a label listed only for the
   other protocol. Unmapped flows are **never treated as normal**. They are left out of training and
   evaluation labels, but they are still real traffic, so the feature module still uses them
   when it computes the 5-minute per-host windows.
5. The protocol comes from the file name: `tcp_complete.csv` and `tcp_nocomplete.csv` are TCP, and
   `udp_complete.csv` is UDP. H-1 checked this against each file's columns.

`label_info.txt` lists 13 benign and 39 malicious TCP labels, and 12 benign and 1 malicious UDP label.

## What this gives on the full dataset (H-1 evidence, 8 networks)

| | flows |
|---|---:|
| normal (0) | 2,845,522 |
| suspicious (1) | 618,878 |
| unmapped (left out) | 942 |
| **total** | **3,465,342** |

The 942 unmapped rows all come from `shaw/tcp_complete.csv`. Their label is empty. They are SMTP
connections (port 25) from two external hosts to the `collinsbecker_mail` server between 25 and 30 Jan 2022.
We do not guess a label for them.

## Points for Malak to look at

* **Labels the publisher calls benign even though an attacker host is involved**:
  `benign DNS - attacker requesting updates` (UDP) and `broken flow - benign` (TCP). We follow the publisher, so both are 0.
* **Half-open TCP is almost all attack traffic**: in `tcp_nocomplete.csv`, 390,756 of 394,636
  flows are suspicious. The current contract has no column for "handshake finished", so the model only
  sees this through the window features (many small connections). If the team wants it as a feature, it
  needs a contract change.
* The AIT role and network columns in the CSVs (e.g. `role_cli = attacker_0`) **give the answer
  away**, so they are not in the feature table. IP addresses are kept, as the team decided on 23 Nov
  (see `docs/contracts/feature_contract.md`).

## Sign-off

- [ ] Malak: rule read, the tests pass (`python -m pytest -q tests/test_h3_labeling.py`), and the counts above are accepted
