# ALL-5 · Demo and presentation runbook

## Who presents what (3–5 slides each, everyone presents their own work)

| Person | Slides | Topic |
|---|---|---|
| Lama | 1, 7, 16 | Opening, architecture, tools and plan |
| Omar | 2, 5, 6, 15 | Problem, research, existing solutions, ATT&CK vs Kill Chain |
| Malak | 3, 4, 17, 18, 19 | Aim, scope, evaluation, risks, conclusion |
| Habiba | 8, 9, 10, 11 | Datasets, AIT contents, features, dataset limits |
| Reem | 12, 13, 14 | Four agents, AIT and the agents, example scenario |

## Live demo (about 5 minutes, Lama drives)

1. **Malak:** load the saved model, replay one test network, and show alerts appearing (score + rule + IPs).
2. **Reem:** open `inc-0001` and show the linked alerts, the link reasons and the one weak link.
3. **Omar:** show the High assessment, its reasons, and that every recommendation is advice only.
4. **Lama:** open the report, click an evidence ID back to the alert, and approve or reject a recommendation.
5. **Habiba:** show the comparison table and the split by network.

**Backup plan:** if the live run fails, run the same steps on `fixtures/` (they always pass `check_contracts.py`) and say so.

## Questions to be ready for (answers are in the deck's speaker notes)

| Question | Who answers | Slide |
|---|---|---|
| Is this an ML project or an agents project? | Lama | 1 |
| Why not just use an existing SIEM? | Omar | 2 |
| How will you prove it works? | Malak | 3, 17 |
| What is actually new? | Omar | 6 |
| Isn't this just a pipeline of four functions? | Reem | 7, 12 |
| Won't the model just learn this one attack? | Habiba | 10 |
| **You kept IP addresses: doesn't the model memorise them?** | Habiba + Malak | 10, 11 |
| How do you stop coincidences becoming incidents? | Reem | 14 |
| How do you know a technique mapping is correct? | Omar | 15 |
| How do you prevent data leakage? | Habiba | 17 |
| What if the hybrid isn't better? | Malak | 17 |

For the IP question: IPs stay in the data so alerts can be linked by host and reports name the machines involved. For the model, say whether they were used as inputs, and show the RF result with the flag on and off if you ran both.

## Rehearsal checklist
- [ ] Full run-through with a timer
- [ ] Each person answers their questions once out loud
- [ ] Demo tested on the presentation laptop
- [ ] Slides 10, 11 and 17 match the final IP decision
