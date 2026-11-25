import numpy as np
import pandas as pd
from sentinelai.detection.evaluation import evaluate_predictions
from sentinelai.detection.rules import detect_rule_hits
from sentinelai.detection.training import split_by_network
from sentinelai.detection.data import FEATURE_COLUMNS


def sample(nets=('a','b','c'),n=30):
 rows=[]
 for j,net in enumerate(nets):
  for i in range(n):
   r={c:0 for c in FEATURE_COLUMNS};r.update(flow_id=f'{net}-{i}',network=net,source_file='tcp_complete.csv',event_end_ms=1_700_000_000_000+i*1000,src_ip='10.0.0.1',dst_ip='10.0.0.2',label_original='x',y=i%2)
   r.update(is_tcp=1,tcp_handshake_complete=0 if i%2 else 1,dst_port=80,dst_port_wellknown=1,duration_ms=10,c_pkts=2,s_pkts=1,c_bytes=100,s_bytes=20,c_bytes_per_pkt=50,s_bytes_per_pkt=20,c_bytes_share=.83,w5_conn_count=15 if i%2 else 2,w5_distinct_dst_ports=14 if i%2 else 1,w5_distinct_dst_hosts=2,w5_dns_count=0,w5_dns_bytes=0,w5_dns_mean_bytes=0)
   rows.append(r)
 return pd.DataFrame(rows)


def test_metrics_confusion_matrix():
 m=evaluate_predictions([0,0,1,1],[0,1,1,0]);assert (m['tn'],m['fp'],m['fn'],m['tp'])==(1,1,1,1);assert m['f1']==.5


def test_multiport_rule_returns_rule_name():
 r=sample(nets=('a',),n=2).iloc[1].to_dict();assert 'R-MULTI-PORT-SCAN' in detect_rule_hits(r)


def test_network_split_has_no_overlap():
 s=split_by_network(sample())
 a=set(s.train.network);b=set(s.validation.network);c=set(s.test.network)
 assert not a&b and not a&c and not b&c


def test_single_network_is_explicitly_development_only():
 s=split_by_network(sample(nets=('fox',)))
 assert s.mode.startswith('DEVELOPMENT_ONLY')
