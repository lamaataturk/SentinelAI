"""R-3 tests: the five linking rules on tiny hand-made alert lists (same cases as the notebook).

Rule 4 and Rule 5 tests that need Kill Chain stages use Omar's O-1 file
(sentinelai/frameworks/technique_stage_mapping.json); they are skipped until it is in the repo.
"""
from dataclasses import replace

import pandas as pd
import pytest

from sentinelai.investigation import knowledge
from sentinelai.investigation.correlation import (
    CorrelationConfig, investigate, link_groups, mark_routine, merge_bursts, routine_baseline,
    summarise_incidents,
)
from sentinelai.investigation.knowledge import O1_RULES

needs_o1 = pytest.mark.skipif(not O1_RULES, reason="needs Omar's O-1 technique_stage_mapping.json")
needs_o3 = pytest.mark.skipif(not knowledge.MAPPER_AVAILABLE, reason="needs Omar's O-3 mapper")

T0 = 1_700_000_000
H = 2 * 3600
IPS = {'web': '10.0.0.1', 'mail': '10.0.0.2', 'fw': '10.0.0.3', 'dns': '10.0.0.4'}
TEST_CFG = CorrelationConfig(baseline_hours=1, routine_min_bins=3)
NORMAL_DAY = [(i * 600, 'mail', 'W-Sys-Cav') for i in range(6)]


def make_alerts(rows):
    a = pd.DataFrame(rows, columns=['dt', 'host', 'short'])
    a['ts'] = T0 + a['dt']
    a = a.sort_values('ts', kind='stable').reset_index(drop=True)
    a['alert_id'] = [f'alert-t-{i:05d}' for i in range(len(a))]
    a['host_ip'] = a['host'].map(IPS)
    a['signature'] = 'test: ' + a['short']
    a['network'] = 't'
    return a.drop(columns='dt')


def pipeline(a, shared_ips=None, **change):
    cfg = replace(TEST_CFG, **change)
    g, g_of_a = merge_bursts(a, cfg.burst_gap_s, cfg.max_group_span_s)
    if shared_ips:
        g['src_ips'] = g['host'].map(lambda h: shared_ips.get(h, []))
    g = mark_routine(g, routine_baseline(a, cfg.baseline_hours), cfg.routine_min_bins, cfg.spike_factor)
    g, links = link_groups(g, cfg.max_gap_s, cfg.strong_gap_s)
    inc = summarise_incidents(g, links)
    a = a.assign(incident_id=g_of_a.map(g.set_index('group_id')['incident_id']).values)
    return a, g, links, inc


def incident_of(a, short):
    return a.loc[a['short'] == short, 'incident_id'].iloc[0]


def test_repeats_within_60s_merge():
    a = make_alerts([(H, 'web', 'A'), (H + 30, 'web', 'A'), (H + 59, 'web', 'A')])
    g, _ = merge_bursts(a)
    assert len(g) == 1 and g['count'].iloc[0] == 3


def test_gap_over_60s_splits():
    g, _ = merge_bursts(make_alerts([(H, 'web', 'A'), (H + 120, 'web', 'A')]))
    assert len(g) == 2


def test_endless_stream_is_capped_at_10_min():
    g, _ = merge_bursts(make_alerts([(H + i * 30, 'web', 'A') for i in range(60)]))
    assert len(g) == 3 and (g['last_ts'] - g['first_ts']).max() < 600


def test_different_types_not_merged():
    g, _ = merge_bursts(make_alerts([(H, 'web', 'A'), (H, 'web', 'B')]))
    assert len(g) == 2


def test_regular_type_at_normal_volume_is_routine():
    a, g, _, _ = pipeline(make_alerts(NORMAL_DAY + [(H, 'mail', 'W-Sys-Cav')]))
    assert g.loc[g['first_ts'] == T0 + H, 'routine'].iloc[0]


def test_spike_of_regular_type_is_kept():
    a, g, _, _ = pipeline(make_alerts(NORMAL_DAY + [(H + i, 'mail', 'W-Sys-Cav') for i in range(10)]))
    row = g.loc[g['first_ts'] == T0 + H].iloc[0]
    assert not row['routine'] and 'spike' in row['why']


def test_type_never_seen_is_kept():
    a, g, _, _ = pipeline(make_alerts(NORMAL_DAY + [(H, 'web', 'X')]))
    row = g.loc[g['short'] == 'X'].iloc[0]
    assert not row['routine'] and 'not seen' in row['why']


def test_same_machine_2_min_apart_linked_strong():
    a, g, links, _ = pipeline(make_alerts(NORMAL_DAY + [(H, 'web', 'A'), (H + 120, 'web', 'B')]))
    assert incident_of(a, 'A') == incident_of(a, 'B') and list(links['strength']) == ['strong']


def test_different_machines_5s_apart_stay_separate():
    a, g, links, _ = pipeline(make_alerts(NORMAL_DAY + [(H, 'web', 'A'), (H + 5, 'fw', 'B')]))
    assert incident_of(a, 'A') != incident_of(a, 'B') and links.empty


def test_gap_of_exactly_45_min_links():
    a, g, links, _ = pipeline(make_alerts(NORMAL_DAY + [(H, 'web', 'A'), (H + 45 * 60, 'web', 'B')]))
    assert incident_of(a, 'A') == incident_of(a, 'B')


def test_gap_over_45_min_stays_separate():
    a, g, links, _ = pipeline(make_alerts(NORMAL_DAY + [(H, 'web', 'A'), (H + 45 * 60 + 1, 'web', 'B')]))
    assert incident_of(a, 'A') != incident_of(a, 'B')


def test_10_min_gap_is_a_weak_link():
    a, g, links, _ = pipeline(make_alerts(NORMAL_DAY + [(H, 'web', 'A'), (H + 600, 'web', 'B')]))
    assert incident_of(a, 'A') == incident_of(a, 'B') and list(links['strength']) == ['weak']


def test_routine_alert_never_links():
    a, g, links, _ = pipeline(make_alerts(NORMAL_DAY + [(H, 'mail', 'A'), (H + 60, 'mail', 'W-Sys-Cav')]))
    r = a.loc[(a['short'] == 'W-Sys-Cav') & (a['ts'] == T0 + H + 60), 'incident_id'].iloc[0]
    assert r != incident_of(a, 'A') and links.empty


def test_shared_attacker_ip_links_two_machines():
    attacker = {'web': ['203.0.113.66'], 'fw': ['203.0.113.66']}
    a, g, links, _ = pipeline(make_alerts(NORMAL_DAY + [(H, 'web', 'A'), (H + 60, 'fw', 'B')]), shared_ips=attacker)
    assert incident_of(a, 'A') == incident_of(a, 'B') and list(links['shared_entity']) == ['ip:203.0.113.66']


def test_confidence_levels():
    def conf(rows):
        a, g, links, inc = pipeline(make_alerts(NORMAL_DAY + rows))
        return inc.set_index('incident_id').loc[incident_of(a, 'A'), 'confidence']
    assert conf([(H, 'web', 'A')]) == 'low'
    assert conf([(H, 'web', 'A'), (H + 120, 'web', 'B')]) == 'high'
    assert conf([(H, 'web', 'A'), (H + 600, 'web', 'B')]) == 'medium'


# ---- Rule 1 keeps IPs, Rule 4 (order), Rule 5 (long gaps)
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


def test_rule1_groups_keep_src_and_dst_ips():
    a = make_alerts2([(H, 'web', 'scan', '203.0.113.66')])
    a.loc[0, 'dst_ip'] = '10.0.0.1'
    g, _ = merge_bursts(a)
    assert g['src_ips'].iloc[0] == ['203.0.113.66'] and g['dst_ips'].iloc[0] == ['10.0.0.1']


@needs_o1
def test_rule4_out_of_order_link_is_kept_but_weak():
    a, g, links, _ = run2([(H, 'web', 'exploit', None), (H + 60, 'web', 'scan', None)])   # scan AFTER exploit
    assert inc2(a, 'exploit') == inc2(a, 'scan'), 'out-of-order step was dropped'
    assert list(links['order']) == ['out_of_order'] and list(links['strength']) == ['weak']


@needs_o1
def test_rule4_in_order_link_stays_strong():
    a, g, links, _ = run2([(H, 'web', 'scan', None), (H + 60, 'web', 'exploit', None)])
    assert list(links['order']) == ['in_order'] and list(links['strength']) == ['strong']


def test_rule4_unknown_stage_does_not_weaken():
    a, g, links, _ = run2([(H, 'web', 'exploit', None), (H + 60, 'web', 'sudo', None)])   # sudo has no stage
    assert list(links['order']) == ['unknown'] and list(links['strength']) == ['strong']


@needs_o1
def test_rule5_joins_later_stage_across_long_gap():
    rows = [(H, 'web', 'exploit', None), (H + 60, 'web', 'cmd', None),
            (H + 5 * 3600, 'fw', 'dns1', IPS['web'])]           # 5 h later, from the web server's IP
    a, g, links, _ = run2(rows)
    assert inc2(a, 'dns1') == inc2(a, 'cmd'), 'long-gap step not joined'
    joined = links[links['long_gap']]
    assert len(joined) == 1 and joined['strength'].iloc[0] == 'weak'
    assert joined['shared_entity'].iloc[0] == f"ip:{IPS['web']}"


@needs_o1
def test_rule5_never_joins_an_earlier_stage():
    rows = [(H, 'web', 'cmd', None), (H + 5 * 3600, 'fw', 'nmap', IPS['web'])]           # scan after C2
    a, g, links, _ = run2(rows)
    assert inc2(a, 'nmap') != inc2(a, 'cmd') and not links['long_gap'].any()


def test_rule5_needs_a_shared_machine_or_ip():
    rows = [(H, 'web', 'cmd', None), (H + 5 * 3600, 'fw', 'dns1', None)]
    a, g, links, _ = run2(rows)
    assert inc2(a, 'dns1') != inc2(a, 'cmd')


def test_rule5_never_joins_steps_without_a_stage():
    rows = [(H, 'web', 'plain', None), (H + 5 * 3600, 'web', 'plain', None)]
    a, g, links, _ = run2(rows)
    assert a.loc[a['ts'] >= T0 + H, 'incident_id'].nunique() == 2


def test_rule5_respects_the_24h_limit():
    rows = [(H, 'web', 'cmd', None), (H + 25 * 3600, 'fw', 'dns1', IPS['web'])]
    a, g, links, _ = run2(rows)
    assert inc2(a, 'dns1') != inc2(a, 'cmd')
