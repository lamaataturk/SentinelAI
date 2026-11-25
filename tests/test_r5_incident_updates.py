"""R-5 tests: IncidentUpdate messages with Omar's mapper (contract, evidence, techniques, stages).

Skipped until Omar's O-1 / O-3 (sentinelai/frameworks/) is in the repo.
"""
import pandas as pd
import pytest

from sentinelai.contracts.messages import validate_bundle, validate_message
from sentinelai.investigation import knowledge
from sentinelai.investigation.correlation import CorrelationConfig, investigate
from sentinelai.investigation.incident_updates import alert_message, incident_updates
from sentinelai.investigation.knowledge import KIND_TECHNIQUE, O1_RULES, OBSERVATION_RULES
from sentinelai.investigation.scenarios import EXPECTED, EXTERNAL_SOURCES, build_scenario_1, build_scenario_2

needs_o1 = pytest.mark.skipif(not O1_RULES, reason="needs Omar's O-1 technique_stage_mapping.json")
needs_o3 = pytest.mark.skipif(not knowledge.MAPPER_AVAILABLE, reason="needs Omar's O-3 mapper")

T0 = 1_700_000_000
H = 2 * 3600
IPS = {'web': '10.0.0.1', 'mail': '10.0.0.2', 'fw': '10.0.0.3', 'dns': '10.0.0.4'}
TEST_CFG = CorrelationConfig(baseline_hours=1, routine_min_bins=3)

SIGS = {'scan': 'Wazuh: Multiple web server 400 error codes from same source ip.',   # T1595, stage 1
        'nmap': 'Suricata: Alert - ET SCAN Possible Nmap User-Agent Observed',      # T1595, stage 1
        'exploit': 'Wazuh: Common web attack.',                                     # T1190, stage 4
        'cmd': 'AMiner: New user_cmd parameter combination in Audit logs.',         # T1059, stage 6
        'sudo': 'Wazuh: Successful sudo to ROOT executed.',                         # T1548.003, no stage
        'dns1': 'AMiner: High entropy in DNS domain.',                              # T1048, stage 7
        'dns2': 'AMiner: New characters in DNS domain.',                            # T1048, stage 7
        'plain': 'test: unmapped alert'}


def make_alerts2(rows):
    """rows = (seconds after T0, machine, signature key, src_ip)"""
    a = pd.DataFrame(rows, columns=['dt', 'host', 'sig', 'src_ip'])
    a['ts'] = T0 + a['dt']
    a = a.sort_values('ts', kind='stable').reset_index(drop=True)
    a['alert_id'] = [f'alert-t-{i:05d}' for i in range(len(a))]
    a['signature'] = a['sig'].map(SIGS)
    a['short'] = a['sig']
    a['host_ip'] = a['host'].map(IPS)
    a['dst_ip'] = None
    a['network'] = 't'
    a['ids_source'] = 'wazuh'
    a['time'] = pd.to_datetime(a['ts'], unit='s', utc=True).dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    return a.drop(columns=['dt', 'sig'])


NORMAL_DAY2 = [(i * 600, 'mail', 'plain', None) for i in range(6)]


def run2(rows):
    return investigate(make_alerts2(NORMAL_DAY2 + rows), TEST_CFG)


def inc2(a, key):
    return a.loc[a['signature'] == SIGS[key], 'incident_id'].iloc[0]


@needs_o1
def test_observation_table_only_uses_weak_kinds():
    assert all(kind.endswith('_suspected') for kind in OBSERVATION_RULES.values())
    assert set(KIND_TECHNIQUE.values()) <= {r['technique_id'] for r in O1_RULES}


@needs_o3
def test_r5_incident_update_follows_contract_and_cites_evidence():
    a, g, links, inc = run2([(H, 'web', 'cmd', None), (H + 60, 'web', 'sudo', None)])
    msgs = incident_updates(a, g, links, inc, 't')
    m = next(x for x in msgs if len(x['alert_ids']) == 2)
    techs = {t['technique_id']: t for t in m['candidate_techniques']}
    assert set(techs) == {'T1059', 'T1548.003'} and all(t['support'] == 'weak' for t in techs.values())
    assert 'rule:O1-T1059' in techs['T1059']['evidence_refs']
    assert m['incident_id'].startswith('inc-t-')
    assert validate_message(m) == []
    alert_msgs = [alert_message(r) for r in a.to_dict('records') if r['alert_id'] in set(m['alert_ids'])]
    assert validate_bundle(alert_msgs + [m]) == [], validate_bundle(alert_msgs + [m])


@needs_o3
def test_r5_stage_needs_two_independent_alert_types():
    one = incident_updates(*run2([(H, 'dns', 'dns1', None)]), 't')
    assert [s['stage'] for m in one for s in m['stage_hypotheses']] == []
    two = incident_updates(*run2([(H, 'dns', 'dns1', None), (H + 30, 'dns', 'dns2', None)]), 't')
    m = next(x for x in two if len(x['alert_ids']) == 2)
    assert [s['stage'] for s in m['stage_hypotheses']] == ['actions_on_objectives']


@needs_o3
def test_r5_innocent_alerts_map_to_nothing():
    msgs = incident_updates(*run2([(H, 'web', 'plain', None)]), 't')
    assert all(m['candidate_techniques'] == [] for m in msgs)


def run_scenario(build):
    alerts_s, truth_s = build()
    name = alerts_s['network'].iloc[0]
    a, g, links, inc = investigate(alerts_s)
    msgs = incident_updates(a, g, links, inc, name, external_sources=EXTERNAL_SOURCES)
    t = a.merge(truth_s, on='alert_id')
    t['kept'] = ~t['incident_id'].isin(set(inc.loc[inc['routine'], 'incident_id']))
    alert_msgs = [alert_message(r) for r in a[a['alert_id'].isin({i for m in msgs for i in m['alert_ids']})].to_dict('records')]
    return name, t, links, msgs, validate_bundle(alert_msgs + msgs)


@needs_o3
def test_scenario_1_web_attack():
    name, t, links, msgs, problems = run_scenario(build_scenario_1)
    attack = set(t.loc[t['gt_incident'].isin(['GT-1', 'GT-2']), 'incident_id'])
    main = next(m for m in msgs if m['incident_id'].replace(f'inc-{name}-', 'inc-') in attack)
    expect = EXPECTED['scenario1']['expected_agent_v2']
    assert not t.loc[t['gt_incident'] == 'normal', 'kept'].any(), 'background not routine'
    assert len(msgs) == expect['non_routine_incidents']
    assert len(attack) == 1, 'attack split'
    assert set(t.loc[t['gt_incident'] == 'benign-1', 'incident_id']).isdisjoint(attack), 'typo joined the attack'
    assert links['long_gap'].sum() == 1 and (links.loc[links['long_gap'], 'strength'] == 'weak').all()
    assert sorted(x['technique_id'] for x in main['candidate_techniques']) == expect['techniques_all_weak']
    assert all(x['support'] == 'weak' for x in main['candidate_techniques'])
    assert [s['stage'] for s in main['stage_hypotheses']] == expect['stages']
    assert problems == []


@needs_o3
def test_scenario_2_innocent_but_noisy():
    name, t, links, msgs, problems = run_scenario(build_scenario_2)
    upd_inc = set(t.loc[t['gt_incident'] == 'benign-update', 'incident_id'])
    upd = next(m for m in msgs if m['incident_id'].replace(f'inc-{name}-', 'inc-') in upd_inc)
    assert not t.loc[t['gt_incident'].isin(['normal', 'benign-monitoring']), 'kept'].any()
    assert len(msgs) == EXPECTED['scenario2']['expected_agent_v2']['non_routine_incidents']
    assert [(x['technique_id'], x['support']) for x in upd['candidate_techniques']] == [('T1548.003', 'weak')]
    assert all(not m['stage_hypotheses'] for m in msgs) and not links['long_gap'].any()
    assert (t[t['kept']].groupby('incident_id')['gt_incident'].nunique() == 1).all(), 'an incident mixes two events'
    assert problems == []
