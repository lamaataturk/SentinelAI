"""R-4 tests: the two demo scenarios, grouping only (predictions written before running).

Technique and stage checks for the same scenarios are in test_r5_incident_updates.py.
"""
import pytest

from sentinelai.investigation.correlation import investigate
from sentinelai.investigation.knowledge import O1_RULES
from sentinelai.investigation.scenarios import EXPECTED, build_scenario_1, build_scenario_2

needs_o1 = pytest.mark.skipif(not O1_RULES, reason="needs Omar's O-1 technique_stage_mapping.json")


def grouped(build):
    alerts_s, truth_s = build()
    a, g, links, inc = investigate(alerts_s)
    t = a.merge(truth_s, on='alert_id')
    t['kept'] = ~t['incident_id'].isin(set(inc.loc[inc['routine'], 'incident_id']))
    return t, links, inc


def test_scenarios_have_ground_truth_and_benign_events():
    for build in (build_scenario_1, build_scenario_2):
        alerts_s, truth_s = build()
        assert not any(c.startswith('gt_') for c in alerts_s.columns), 'answers leaked into the alerts'
        assert len(alerts_s) == len(truth_s) and truth_s['gt_incident'].str.startswith('benign').any()


@needs_o1
def test_scenario_1_whole_attack_is_one_incident():
    t, links, inc = grouped(build_scenario_1)
    attack = set(t.loc[t['gt_incident'].isin(['GT-1', 'GT-2']), 'incident_id'])
    assert not t.loc[t['gt_incident'] == 'normal', 'kept'].any(), 'background not routine'
    assert int((~inc['routine']).sum()) == EXPECTED['scenario1']['expected_agent_v2']['non_routine_incidents']
    assert len(attack) == 1, 'attack split'
    assert set(t.loc[t['gt_incident'] == 'benign-1', 'incident_id']).isdisjoint(attack), 'typo joined the attack'
    assert links['long_gap'].sum() == 1 and (links.loc[links['long_gap'], 'strength'] == 'weak').all()


def test_scenario_2_innocent_events_stay_apart():
    t, links, inc = grouped(build_scenario_2)
    assert not t.loc[t['gt_incident'].isin(['normal', 'benign-monitoring']), 'kept'].any()
    assert int((~inc['routine']).sum()) == EXPECTED['scenario2']['expected_agent_v2']['non_routine_incidents']
    assert not links['long_gap'].any()
    assert (t[t['kept']].groupby('incident_id')['gt_incident'].nunique() == 1).all(), 'an incident mixes two events'
