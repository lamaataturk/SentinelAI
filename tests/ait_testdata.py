"""Test data for H-3/H-4: the exact raw AIT Netflow headers (copied from the H-1
Step 4 output, identical in all 8 networks), label_info.txt verbatim, and small
builders for raw AIT zips and normalised flow tables."""
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

TCP_COMPLETE = "#15#c_ip:1,c_port:2,c_pkts_all:3,c_rst_cnt:4,c_ack_cnt:5,c_ack_cnt_p:6,c_bytes_uniq:7,c_pkts_data:8,c_bytes_all:9,c_pkts_retx:10,c_bytes_retx:11,c_pkts_ooo:12,c_syn_cnt:13,c_fin_cnt:14,s_ip:15,s_port:16,s_pkts_all:17,s_rst_cnt:18,s_ack_cnt:19,s_ack_cnt_p:20,s_bytes_uniq:21,s_pkts_data:22,s_bytes_all:23,s_pkts_retx:24,s_bytes_retx:25,s_pkts_ooo:26,s_syn_cnt:27,s_fin_cnt:28,first:29,last:30,durat:31,c_first:32,s_first:33,c_last:34,s_last:35,c_first_ack:36,s_first_ack:37,c_isint:38,s_isint:39,c_iscrypto:40,s_iscrypto:41,con_t:42,p2p_t:43,http_t:44,c_rtt_avg:45,c_rtt_min:46,c_rtt_max:47,c_rtt_std:48,c_rtt_cnt:49,c_ttl_min:50,c_ttl_max:51,s_rtt_avg:52,s_rtt_min:53,s_rtt_max:54,s_rtt_std:55,s_rtt_cnt:56,s_ttl_min:57,s_ttl_max:58,p2p_st:59,ed2k_data:60,ed2k_sig:61,ed2k_c2s:62,ed2k_c2c:63,ed2k_chat:64,c_f1323_opt:65,c_tm_opt:66,c_win_scl:67,c_sack_opt:68,c_sack_cnt:69,c_mss:70,c_mss_max:71,c_mss_min:72,c_win_max:73,c_win_min:74,c_win_0:75,c_cwin_max:76,c_cwin_min:77,c_cwin_ini:78,c_pkts_rto:79,c_pkts_fs:80,c_pkts_reor:81,c_pkts_dup:82,c_pkts_unk:83,c_pkts_fc:84,c_pkts_unrto:85,c_pkts_unfs:86,c_syn_retx:87,s_f1323_opt:88,s_tm_opt:89,s_win_scl:90,s_sack_opt:91,s_sack_cnt:92,s_mss:93,s_mss_max:94,s_mss_min:95,s_win_max:96,s_win_min:97,s_win_0:98,s_cwin_max:99,s_cwin_min:100,s_cwin_ini:101,s_pkts_rto:102,s_pkts_fs:103,s_pkts_reor:104,s_pkts_dup:105,s_pkts_unk:106,s_pkts_fc:107,s_pkts_unrto:108,s_pkts_unfs:109,s_syn_retx:110,http_req_cnt:111,http_res_cnt:112,http_res:113,c_pkts_push:114,s_pkts_push:115,c_tls_SNI:116,s_tls_SCN:117,c_npnalpn:118,s_npnalpn:119,c_tls_sesid:120,c_last_handshakeT:121,s_last_handshakeT:122,c_appdataT:123,s_appdataT:124,c_appdataB:125,s_appdataB:126,fqdn:127,dns_rslv:128,req_tm:129,res_tm:130,timestamp,role_cli,ipv4_address_cli,network_cli,role_serv,ipv4_address_serv,network_serv,label"
TCP_NOCOMPLETE = "#15#c_ip:1,c_port:2,c_pkts_all:3,c_rst_cnt:4,c_ack_cnt:5,c_ack_cnt_p:6,c_bytes_uniq:7,c_pkts_data:8,c_bytes_all:9,c_pkts_retx:10,c_bytes_retx:11,c_pkts_ooo:12,c_syn_cnt:13,c_fin_cnt:14,s_ip:15,s_port:16,s_pkts_all:17,s_rst_cnt:18,s_ack_cnt:19,s_ack_cnt_p:20,s_bytes_uniq:21,s_pkts_data:22,s_bytes_all:23,s_pkts_retx:24,s_bytes_retx:25,s_pkts_ooo:26,s_syn_cnt:27,s_fin_cnt:28,first:29,last:30,durat:31,c_first:32,s_first:33,c_last:34,s_last:35,c_first_ack:36,s_first_ack:37,c_isint:38,s_isint:39,c_iscrypto:40,s_iscrypto:41,con_t:42,p2p_t:43,http_t:44,timestamp,role_cli,ipv4_address_cli,network_cli,role_serv,ipv4_address_serv,network_serv,label"
UDP_COMPLETE = "#c_ip:1,c_port:2,c_first_abs:3,c_durat:4,c_bytes_all:5,c_pkts_all:6,c_isint:7,c_iscrypto:8,c_type:9,s_ip:10,s_port:11,s_first_abs:12,s_durat:13,s_bytes_all:14,s_pkts_all:15,s_isint:16,s_iscrypto:17,s_type:18,fqdn:19,timestamp,rounded_timestamp,role_cli,ipv4_address_cli,network_cli,role_serv,ipv4_address_serv,network_serv,label"
LABEL_INFO = "\r\n".join([
 "Benign labels in TCP:", "browsing/update", "benign_share", "broken flow - benign", "mail", "monitoring",
 "HTTP(S) intra", "HTTP(S) DMZ", "HTTP", "HTTPS", "DNS", "SSH", "proxy", "update/command on unassigned port", "",
 "Malicious labels in TCP:", "service_scan", "online_cracking", "host_discover_dmz", "host_discover_local",
 "wpscan", "dirb_scan", "upload_rce_shell", "check_user_id", "check_netstat_t", "read_resolv",
 "check_network_config", "check_ps_a", "check_release", "read_group", "read_passwd", "check_date",
 "list_web_dir", "check_wp_config", "dump_wp_users", "read_profile", "dns_brute_force_start", "list_www",
 "check_who", "clear", "check_last", "check_id", "vpn_connect", "check_whoami", "check_uname_r",
 "check_meminfo", "check_uname_a", "check_df", "check_netstat_nat", "list_home", "check_netstat_l",
 "check_cpuinfo", "check_uptime", "check_pwd", "list_l", "",
 "Benign labels in UDP:", "mDNSv6", "mDNS", "bootp", "NTP", "systemd-resolver (local)",
 "benign DNS - attacker requesting updates", "benign DNS", "OpenVPN", "QUIC", "STUN VoIP", "NetBIOS", "GoogleDNS", "",
 "Malicious labels in UDP:", "data exfiltration"])


T0 = 1_642_204_800_000.0   # 2022-01-15 00:00:00 UTC in ms


def _raw_rows(header: str, rows: list[dict]) -> str:
    """CSV text with the REAL header; unspecified fields are filled with '0'."""
    from sentinelai.data.features import clean_column
    clean = [clean_column(h) for h in header.split(",")]
    lines = [header] + [",".join(str(r.get(c, "0")) for c in clean) for r in rows]
    return "\r\n".join(lines) + "\r\n"


def tcp_row(c_ip, s_ip, s_port, first, durat_ms, label, c_bytes=100, s_bytes=200, c_pkts=3, s_pkts=4):
    return {"c_ip": c_ip, "c_port": 40000, "s_ip": s_ip, "s_port": s_port, "first": first,
            "last": first + durat_ms, "durat": durat_ms, "c_bytes_all": c_bytes, "s_bytes_all": s_bytes,
            "c_pkts_all": c_pkts, "s_pkts_all": s_pkts, "role_cli": "attacker_0", "label": label}


def udp_row(c_ip, s_ip, s_port, first, durat_s, label, c_bytes=60, s_bytes=90, c_pkts=1, s_pkts=1):
    return {"c_ip": c_ip, "c_port": 5353, "s_ip": s_ip, "s_port": s_port, "c_first_abs": first,
            "c_durat": durat_s, "c_bytes_all": c_bytes, "c_pkts_all": c_pkts,
            "s_first_abs": first + 1 if s_pkts else 0, "s_durat": durat_s if s_pkts else 0,
            "s_bytes_all": s_bytes, "s_pkts_all": s_pkts, "label": label}


def make_zip(path: Path, tcp: list[dict], nocomplete: list[dict], udp: list[dict]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("tcp_complete.csv", _raw_rows(TCP_COMPLETE, tcp))
        z.writestr("tcp_nocomplete.csv", _raw_rows(TCP_NOCOMPLETE, nocomplete))
        z.writestr("udp_complete.csv", _raw_rows(UDP_COMPLETE, udp))
    return path


def random_flows(n=1500, hosts=12, seed=0, network="net", span_ms=40 * 60_000, tie_every=7):
    """Normalised flow table (as normalise_flows() returns), shuffled, with many same-time ties."""
    rng = np.random.default_rng(seed)
    t = np.sort(T0 + rng.integers(0, span_ms, n).astype(float))
    t[::tie_every] = t[np.maximum(np.arange(0, n, tie_every) - 1, 0)]     # force exact ties
    is_tcp = rng.random(n) < 0.6
    port = np.where(rng.random(n) < 0.25, 53, rng.choice([22, 25, 80, 443, 8080, 3306, 6000], n))
    df = pd.DataFrame({
        "flow_id": [f"f-{network}-x-{i:07d}" for i in range(n)], "network": network,
        "source_file": np.where(is_tcp, "tcp_complete.csv", "udp_complete.csv"),
        "protocol_name": np.where(is_tcp, "TCP", "UDP"),
        "start_ms": t, "end_ms": t + rng.integers(0, 5000, n),
        "src_ip": rng.choice([f"10.0.0.{i}" for i in range(hosts)], n),
        "dst_ip": rng.choice([f"192.168.1.{i}" for i in range(30)], n),
        "src_port": rng.integers(1024, 65535, n), "dst_port": port.astype("int64"),
        "bytes": rng.integers(0, 9000, n), "packets": rng.integers(0, 50, n), "label_raw": "x",
    })
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)
