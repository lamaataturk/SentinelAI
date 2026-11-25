# Investigation Agent · decisions and results (Reem, 24 Nov 2026)

Data: AIT Alert Data Set (AIT-ADS), authors' CSV export, 2,655,821 alerts from 8 networks.
The CSV has the IP of the host that raised each alert but no source/destination IPs.

Split, fixed before tuning: **tuning** russellmitchell, santos, shaw · **final test (run once)** fox, harrison, wardbeck, wheeler, wilson.
"Attack" = an alert with an exact attack label inside an attack-phase window.

Reproduce:

```
python scripts/prepare_ait_ads.py --csv-dir data/raw/alerts_csv
python scripts/run_investigation.py --tuning
python scripts/run_investigation.py --test
python scripts/run_investigation.py --scenarios
```

## Decision 1 (23 Nov): link gap 45 min, was 30

| Gap | Attack split into (rm / santos / shaw) | Privilege escalation in main incident | Purity (rm / santos / shaw) |
|---|---|---|---|
| 30 min | 9 / 8 / 5 | no | 0.982 / 0.994 / 1.000 |
| **45 min** | **8 / 7 / 4** | **yes, all 3** | **0.982 / 0.994 / 1.000** |
| 60 min | 8 / 7 / 4 | yes | 0.982 / 0.992 / 1.000 |
| 90 min | 8 / 7 / 4 | yes | 0.981 / 0.991 / 0.993 |

45 min is the smallest gap that joins privilege escalation to the main web-server incident on all three networks with no loss of purity.

## Decision 2 (23 Nov): routine filter stays at 6 slots, 3× spike

| Min slots | Attack kept (worst network) | False alarms kept (avg, 3×) | Verdict |
|---|---|---|---|
| 3 | 99.95% | 2.0% | rejected: drops privilege-escalation evidence |
| **6** | **99.98%** | **2.7%** | **chosen** |
| 12 | 100% | 7.4% | rejected: about 3× more false alarms for one weak alert |

## Final test (R-6), run once with frozen settings

| Network | Alerts | Attack kept | False alarms kept | Attack split into | Biggest incident's share | Purity | Main incident techniques (all weak) | Contract problems |
|---|---|---|---|---|---|---|---|---|
| fox | 473,104 | 1.000 | 0.023 | 8 | 1.000 | 1.000 | T1190, T1548.003, T1595 | 0 |
| harrison | 593,948 | 0.998 | 0.008 | 6 | 1.000 | 1.000 | T1059, T1190, T1548.003, T1595 | 0 |
| wardbeck | 91,257 | 1.000 | 0.021 | 5 | 0.997 | 0.993 | T1059, T1190, T1548.003, T1595 | 0 |
| wheeler | 616,161 | 1.000 | 0.008 | 8 | 1.000 | 1.000 | T1190, T1595 | 0 |
| wilson | 634,246 | 1.000 | 0.008 | 8 | 1.000 | 0.999 | T1190, T1548.003, T1595 | 0 |
| **mean** | | **1.000** | **0.014** | **7.0** | **0.999** | **0.998** | | **0** |

Tuning means for comparison: attack kept 1.000, false alarms 0.027, split into 6.3, biggest share 0.997, purity 0.992. Main incident stage: reconnaissance on all 5 test networks. Rule 5 joins: 0.

On fox, harrison, wheeler and wilson, 69–89% of all alerts are kept because the attacker's `dirb` scan alone made about 410,000 alerts there; most alerts really are attack alerts. The false-alarm rate is the number that matters.

## Demo scenarios

- **Scenario 1 (web attack):** the whole attack is one incident, the DNS theft 6 h later joins by a weak long-gap link, the mistyped password stays alone. Techniques (all weak): T1048, T1059, T1190, T1548.003, T1595; stages: reconnaissance, actions on objectives.
- **Scenario 2 (innocent but noisy):** 4 incidents, monitoring scan routine, the admin's sudo gets only weak T1548.003 (must be rated Low), no stages, no long-gap joins.

## Limitations

- The attack is still split into 5–8 incidents; the extra pieces are small, often steps on other hosts with no shared IP in the CSV.
- All techniques are weak (IDS alert names only); the Response Agent must not treat them as proof.
- Only reconnaissance gets a Kill Chain stage on real data.
- T1505.003 (web shell) is never mapped: no AIT alert type specifically shows a web shell.
- Rule 5 makes no joins on real data (no src/dst IPs in the CSV); it works in Scenario 1.
- Some innocent incidents get one weak technique (e.g. admin sudo → T1548.003).
