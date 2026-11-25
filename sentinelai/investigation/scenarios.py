"""Demo scenarios 1 and 2 (v2, real AIT-ADS alert names) with expectations written before running.

* Scenario 1: a web attack (scan, exploit, web shell, commands, sudo, DNS theft 6 h later)
  plus one innocent mistyped mail password.
* Scenario 2: innocent but noisy (monitoring scan, backup, admin updates + sudo, antivirus).

build_scenario_1() / build_scenario_2() return (alerts, truth). The agent gets only alerts.
write_scenarios(folder) writes <name>_alerts.csv, <name>_truth.csv, <name>_expected.json.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

ATTACKER = '203.0.113.66'
MACHINE_IP = {'webserver': '10.0.1.20', 'inet-firewall': '10.0.1.1', 'mail': '10.0.1.25',
              'inet-dns': '10.0.1.53', 'vpn': '10.0.1.10', 'monitoring': '10.0.1.5',
              'internal_share': '10.0.1.40', 'backup': '10.0.1.30'}
SIG = {   # real AIT-ADS signatures used by the scenarios
    'clamav': ('wazuh', 'W-Sys-Cav', 'Wazuh: ClamAV database update'),
    'ids_evt': ('wazuh', 'W-All-Evt', 'Wazuh: IDS event.'),
    'nmap': ('suricata', 'S-Flw-Nmp', 'Suricata: Alert - ET SCAN Possible Nmap User-Agent Observed'),
    'mail_inv': ('wazuh', 'W-Mai-Inv', 'Wazuh: Dovecot Invalid User Login Attempt.'),
    'web400': ('wazuh', 'W-Acc-400', 'Wazuh: Web server 400 error code.'),
    'web400_multi': ('wazuh', 'W-All-Mul3', 'Wazuh: Multiple web server 400 error codes from same source ip.'),
    'new_method': ('aminer', 'A-Acc-Val1', 'AMiner: New request method in Apache Access log.'),
    'forbidden': ('wazuh', 'W-Err-Fbd2', 'Wazuh: Apache: Attempt to access forbidden file or directory.'),
    'web_attack': ('wazuh', 'W-Acc-Att', 'Wazuh: Common web attack.'),
    'suspicious_url': ('wazuh', 'W-Acc-Sus', 'Wazuh: Suspicious URL access.'),
    'user_cmd': ('aminer', 'A-Aud-Com6', 'AMiner: New user_cmd parameter combination in Audit logs.'),
    'pam_open': ('wazuh', 'W-Aut-Pam1', 'Wazuh: PAM: Login session opened.'),
    'sudo_first': ('wazuh', 'W-Aut-Sud', 'Wazuh: First time user executed sudo.'),
    'sudo_root': ('wazuh', 'W-Aut-Sud', 'Wazuh: Successful sudo to ROOT executed.'),
    'dns_entropy': ('aminer', 'A-Dns-Ent', 'AMiner: High entropy in DNS domain.'),
    'dns_chars': ('aminer', 'A-Dns-Chr', 'AMiner: New characters in DNS domain.'),
    'apt': ('suricata', 'S-Flw-Apt', 'Suricata: Alert - ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management'),
    'new_event': ('aminer', 'A-All-Evt', 'AMiner: New event type.'),
}


def _finish(rows, name, day0):
    t0 = int(pd.Timestamp(day0, tz='UTC').timestamp())
    df = pd.DataFrame(rows)
    df['ts'] = t0 + df['dt']
    df = df.sort_values('ts', kind='stable').reset_index(drop=True)
    df['alert_id'] = [f'alert-{name}-{i:05d}' for i in range(len(df))]
    df['network'] = name
    df['time'] = pd.to_datetime(df['ts'], unit='s', utc=True).dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    df['host_ip'] = df['host'].map(MACHINE_IP)
    agent_cols = ['alert_id', 'network', 'ts', 'time', 'ids_source', 'signature', 'short',
                  'host', 'host_ip', 'src_ip', 'dst_ip']
    truth_cols = ['alert_id', 'gt_incident', 'gt_step', 'gt_technique', 'gt_stage']
    return df[agent_cols], df[truth_cols]


def _adder(rows):
    def add(dt, host, sig, src_ip=None, dst_ip=None, gt='normal', step='normal', technique=None, stage=None):
        tool, short, signature = SIG[sig]
        rows.append(dict(dt=dt, host=host, ids_source=tool, short=short, signature=signature,
                         src_ip=src_ip, dst_ip=dst_ip, gt_incident=gt, gt_step=step,
                         gt_technique=technique, gt_stage=stage))
    return add


def _background(add):
    for t in range(0, 2 * 86400, 600):
        add(t, 'mail', 'clamav')
    for t in range(300, 2 * 86400, 1800):
        add(t, 'vpn', 'ids_evt')
        add(t + 5, 'inet-firewall', 'ids_evt')


def build_scenario_1():
    """Web attack. Day 1 normal; day 2 10:00 attacker 203.0.113.66."""
    rows = []
    add = _adder(rows)
    _background(add)
    A, web = 86400 + 10 * 3600, MACHINE_IP['webserver']
    for i in range(20):                                   # 1 network scan (firewall sees it)
        add(A + 2 * i, 'inet-firewall', 'nmap', ATTACKER, f'10.0.1.{1 + i}',
            'GT-1', 'network_scan', 'T1595', 'reconnaissance')
    add(A + 5, 'mail', 'mail_inv', '10.0.2.15', MACHINE_IP['mail'], 'benign-1', 'typo_login')   # coincidence
    for i in range(50):                                   # 2 service scan of the web server
        add(A + 120 + i, 'webserver', 'web400', ATTACKER, web, 'GT-1', 'service_scan', 'T1595', 'reconnaissance')
    for i in range(5):
        add(A + 125 + 10 * i, 'webserver', 'web400_multi', ATTACKER, web, 'GT-1', 'service_scan', 'T1595', 'reconnaissance')
    for i in range(100):                                  # 3 wordlist scan (dirb / wpscan)
        add(A + 240 + i, 'webserver', 'new_method', ATTACKER, web, 'GT-1', 'wordlist_scan', 'T1595', 'reconnaissance')
        add(A + 240 + i, 'webserver', 'forbidden', ATTACKER, web, 'GT-1', 'wordlist_scan', 'T1595', 'reconnaissance')
    for i in range(2):                                    # 4 exploit through the WordPress plugin
        add(A + 400 + i, 'webserver', 'web_attack', ATTACKER, web, 'GT-1', 'upload_exploit', 'T1190', 'exploitation')
    add(A + 405, 'webserver', 'suspicious_url', ATTACKER, web, 'GT-1', 'web_shell', 'T1505.003', 'installation')  # 5
    for i in range(5):                                    # 6 commands through the web shell
        add(A + 480 + 40 * i, 'webserver', 'user_cmd', None, None, 'GT-1', 'commands', 'T1059', 'command_and_control')
    add(A + 2400, 'webserver', 'pam_open', None, None, 'GT-1', 'privilege_escalation', 'T1548.003', None)   # 7
    add(A + 2401, 'webserver', 'sudo_first', None, None, 'GT-1', 'privilege_escalation', 'T1548.003', None)
    for i in range(2):
        add(A + 2402 + 10 * i, 'webserver', 'sudo_root', None, None, 'GT-1', 'privilege_escalation', 'T1548.003', None)
    for i in range(40):                                   # 8 data theft over DNS, 6 h later
        add(A + 6 * 3600 + 30 * i, 'inet-dns', 'dns_entropy', web, MACHINE_IP['inet-dns'],
            'GT-2', 'dns_exfiltration', 'T1048', 'actions_on_objectives')
    for i in range(5):
        add(A + 6 * 3600 + 15 + 120 * i, 'inet-dns', 'dns_chars', web, MACHINE_IP['inet-dns'],
            'GT-2', 'dns_exfiltration', 'T1048', 'actions_on_objectives')
    return _finish(rows, 'scenario1', '2026-01-10')


def build_scenario_2():
    """Innocent but noisy. No attacker."""
    rows = []
    add = _adder(rows)
    _background(add)
    for h in range(48):                                   # hourly monitoring scan (same Nmap signature)
        for i in range(10):
            add(h * 3600 + 900 + 2 * i, 'inet-firewall', 'nmap', MACHINE_IP['monitoring'], f'10.0.1.{20 + i}',
                'benign-monitoring', 'monitoring_scan')
    for night in (1, 2):                                  # nightly backup 02:00, 15 min
        for i in range(30):
            add((night - 1) * 86400 + 2 * 3600 + 30 * i, 'internal_share', 'new_event',
                MACHINE_IP['backup'], MACHINE_IP['internal_share'], f'benign-backup-{night}', 'backup')
    D2 = 86400
    for i in range(8):                                    # package updates, then admin sudo
        add(D2 + 11 * 3600 + 15 * i, 'webserver', 'apt', MACHINE_IP['webserver'], '198.51.100.200',
            'benign-update', 'update')
    for i in range(2):
        add(D2 + 11 * 3600 + 150 + 10 * i, 'webserver', 'sudo_root', None, None, 'benign-update', 'admin_sudo')
    for i in range(60):                                   # antivirus full refresh 3 min later
        add(D2 + 11 * 3600 + 180 + i, 'mail', 'clamav', gt='benign-av-refresh', step='av_refresh')
    return _finish(rows, 'scenario2', '2026-01-20')


EXPECTED = {
    'scenario1': {
        'story': ('Outside attacker 203.0.113.66 scans the network, attacks the WordPress web server, opens a web '
                  'shell, runs commands, escalates to root with sudo, and 6 h later leaks data over DNS. An employee '
                  'mistypes a mail password 5 s after the scan starts.'),
        'ground_truth': {
            'GT-1': {'steps': ['network_scan', 'service_scan', 'wordlist_scan', 'upload_exploit', 'web_shell',
                               'commands', 'privilege_escalation'],
                     'true_techniques': ['T1595', 'T1190', 'T1505.003', 'T1059', 'T1548.003'],
                     'expected_severity': 'High'},
            'GT-2': {'steps': ['dns_exfiltration'], 'true_techniques': ['T1048'], 'expected_severity': 'High',
                     'note': 'same attack story as GT-1'},
            'benign-1': {'what': 'employee mistypes a mail password', 'expected_severity': 'Low'}},
        'expected_agent_v2': {
            'non_routine_incidents': 2,
            'attack': ('ONE incident: firewall scan joined by the shared attacker IP (Rule 3), all web-server steps, '
                       'privilege escalation by a weak link, DNS theft by a weak long-gap link (Rule 5)'),
            'benign-1': 'alone',
            'techniques_all_weak': ['T1048', 'T1059', 'T1190', 'T1548.003', 'T1595'],
            'stages': ['reconnaissance', 'actions_on_objectives'],
            'not_mapped': {'T1505.003': 'no AIT signature specifically shows a web shell'}}},
    'scenario2': {
        'story': ('No attacker. Hourly monitoring scan, nightly backup at 02:00, admin installs updates and uses sudo, '
                  'antivirus full refresh 3 minutes later.'),
        'ground_truth': {'benign-monitoring': {'expected_severity': 'none (routine)'},
                         'benign-backup-1': {'expected_severity': 'Low'}, 'benign-backup-2': {'expected_severity': 'Low'},
                         'benign-update': {'expected_severity': 'Low', 'note': 'weak T1548.003 is expected; must stay Low'},
                         'benign-av-refresh': {'expected_severity': 'Low'}},
        'pass_condition_whole_system': 'no incident rated High or Critical',
        'expected_agent_v2': {'non_routine_incidents': 4, 'update_incident_techniques': ['T1548.003'],
                              'stages': [], 'long_gap_joins': 0}},
}


def write_scenarios(folder) -> dict:
    """Writes both scenarios to folder; returns {name: (alerts, truth)}."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    out = {}
    for build in (build_scenario_1, build_scenario_2):
        alerts_s, truth_s = build()
        name = alerts_s["network"].iloc[0]
        out[name] = (alerts_s, truth_s)
        alerts_s.to_csv(folder / f"{name}_alerts.csv", index=False)
        truth_s.to_csv(folder / f"{name}_truth.csv", index=False)
        (folder / f"{name}_expected.json").write_text(json.dumps(EXPECTED[name], indent=2) + "\n")
    return out
