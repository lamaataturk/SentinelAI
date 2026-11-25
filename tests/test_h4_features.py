"""H-4: feature module. 'Done when': tests prove the windows never look into the future."""
import numpy as np
import pandas as pd
import pytest

import ait_testdata as T
from sentinelai.contracts.features import (ALL_COLUMNS, WINDOW_FEATURES, add_ip_model_features,
                                           model_input_columns, validate_feature_frame)
from sentinelai.data import features as F
from sentinelai.data.labeling import parse_label_info_text

W = F.WINDOW_MS


@pytest.fixture
def label_map():
    return parse_label_info_text(T.LABEL_INFO)


def naive_windows(flows: pd.DataFrame) -> pd.DataFrame:
    """Reference straight from the contract, O(n^2): same network, same src_ip,
    start time in [t - 5 min, t)."""
    out = []
    for _, r in flows.iterrows():
        t = r.start_ms
        p = flows[(flows.network == r.network) & (flows.src_ip == r.src_ip)
                  & (flows.start_ms >= t - W) & (flows.start_ms < t)]
        dns = p[p.dst_port == 53]
        out.append({"win5_conn_count": len(p), "win5_distinct_dst_ports": p.dst_port.nunique(),
                    "win5_distinct_dst_hosts": p.dst_ip.nunique(), "win5_dns_count": len(dns),
                    "win5_dns_avg_bytes": float(dns.bytes.mean()) if len(dns) else 0.0})
    return pd.DataFrame(out, index=flows.index)


def one_flow(i, t, host="10.0.0.1", port=80, network="n"):
    return {"flow_id": f"f-{network}-x-{i:07d}", "network": network, "source_file": "tcp_complete.csv",
            "protocol_name": "TCP", "start_ms": float(t), "end_ms": float(t) + 10, "src_ip": host,
            "dst_ip": f"10.9.0.{i % 250}", "src_port": 40000, "dst_port": port, "bytes": 20, "packets": 2,
            "label_raw": "x"}


# ---------------------------------------------------------------- definition
@pytest.mark.parametrize("seed", [0, 1, 2])
def test_windows_match_the_contract_definition(seed):
    flows = T.random_flows(n=700, seed=seed)
    got = F.compute_features(flows)[WINDOW_FEATURES].astype(float)
    pd.testing.assert_frame_equal(got, naive_windows(flows).astype(float))


def test_window_boundaries():
    t = T.T0 + 10 * W
    flows = pd.DataFrame([one_flow(0, t - W - 1), one_flow(1, t - W), one_flow(2, t - 1),
                          one_flow(3, t), one_flow(4, t), one_flow(5, t + 1)])
    w = F.compute_features(flows).set_index("flow_id")["win5_conn_count"]
    assert w["f-n-x-0000000"] == 0
    assert w["f-n-x-0000003"] == 2 and w["f-n-x-0000004"] == 2   # t-W and t-1 count; the tie at t does not
    assert w["f-n-x-0000005"] == 3                               # window [t+1-W, t+1): t-1, t, t


# ---------------------------------------------------------------- no future
@pytest.mark.parametrize("seed", [0, 1, 2, 3])
def test_removing_the_future_changes_nothing(seed):
    flows = T.random_flows(n=2000, seed=seed)
    full = F.compute_features(flows).set_index("flow_id")
    for q in (0.1, 0.35, 0.6, 0.9):
        cut = flows.start_ms.quantile(q)
        part = F.compute_features(flows[flows.start_ms < cut]).set_index("flow_id")
        pd.testing.assert_frame_equal(part, full.loc[part.index])


@pytest.mark.parametrize("seed", [0, 1])
def test_changing_the_future_changes_nothing(seed):
    """Rewrite every flow starting at/after a cut and add a flood of future DNS flows
    from the same hosts; rows before the cut must not move."""
    rng = np.random.default_rng(seed)
    flows = T.random_flows(n=2000, seed=seed)
    cut = flows.start_ms.quantile(0.5)
    before = F.compute_features(flows).set_index("flow_id")
    fut = flows.start_ms >= cut
    changed = flows.copy()
    changed.loc[fut, "dst_port"] = rng.integers(1, 65535, fut.sum())
    changed.loc[fut, "bytes"] = 10**6
    changed.loc[fut, "dst_ip"] = "203.0.113.66"
    flood = pd.concat([changed[fut]] * 3, ignore_index=True)
    flood["flow_id"] = [f"f-net-flood-{i:07d}" for i in range(len(flood))]
    flood["dst_port"] = 53
    flood["start_ms"] = cut + rng.integers(0, 3 * W, len(flood))
    flood["end_ms"] = flood["start_ms"] + 5
    after = F.compute_features(pd.concat([changed, flood], ignore_index=True)).set_index("flow_id")
    past = flows.loc[~fut, "flow_id"]
    pd.testing.assert_frame_equal(after.loc[past], before.loc[past])


def test_ties_do_not_see_each_other():
    t = T.T0 + W
    flows = pd.DataFrame([one_flow(0, t - 5)] + [one_flow(i, t, port=1000 + i) for i in range(1, 50)])
    w = F.compute_features(flows)
    later = w.flow_id != "f-n-x-0000000"
    assert (w.loc[later, "win5_conn_count"] == 1).all() and (w.loc[later, "win5_distinct_dst_ports"] == 1).all()


# ---------------------------------------------------------------- one code path
def test_runtime_equals_batch():
    flows = T.random_flows(n=1500, seed=5)
    batch = F.compute_features(flows).set_index("flow_id")
    ext = F.FlowFeatureExtractor()
    live = {r.flow_id: ext.process(r.to_dict()) for _, r in flows.sort_values(["start_ms", "flow_id"]).iterrows()}
    live = pd.DataFrame.from_dict(live, orient="index")
    cols = list(live.columns)
    pd.testing.assert_frame_equal(live.loc[batch.index, cols].astype(float), batch[cols].astype(float),
                                  check_names=False)


def test_runtime_refuses_out_of_order_flows():
    ext = F.FlowFeatureExtractor()
    ext.process(one_flow(0, T.T0 + 1000))
    with pytest.raises(ValueError, match="out of time order"):
        ext.process(one_flow(1, T.T0 + 999))


def test_input_row_order_does_not_matter():
    flows = T.random_flows(n=1200, seed=7)
    a = F.compute_features(flows).set_index("flow_id").sort_index()
    b = F.compute_features(flows.sample(frac=1, random_state=99)).set_index("flow_id").sort_index()
    pd.testing.assert_frame_equal(a, b)


def test_networks_do_not_share_windows():
    a, b = T.random_flows(n=600, seed=1, network="a"), T.random_flows(n=600, seed=2, network="b")
    together = F.compute_features(pd.concat([a, b], ignore_index=True)).set_index("flow_id")
    alone = pd.concat([F.compute_features(a), F.compute_features(b)]).set_index("flow_id")
    pd.testing.assert_frame_equal(together.loc[alone.index], alone)


# ---------------------------------------------------------------- contract + raw AIT files
def test_output_follows_the_team_contract(label_map):
    flows = T.random_flows(n=500)
    flows["label_raw"] = np.where(flows.protocol_name == "TCP", "mail", "NTP")   # benign TCP / UDP labels
    table, unmapped = F.build_feature_table(flows, label_map)
    assert list(table.columns) == ALL_COLUMNS
    assert validate_feature_frame(table) == []
    assert len(unmapped) == 0
    df = add_ip_model_features(table)                      # IPs kept and usable as model inputs
    assert all(pd.api.types.is_numeric_dtype(df[c]) for c in model_input_columns())


def test_real_headers_end_to_end(tmp_path, label_map):
    t = T.T0 + 3 * W
    z = T.make_zip(tmp_path / "toy_netflows.zip",
                   tcp=[T.tcp_row("10.0.0.1", "10.0.0.9", 80, t - 60_000, 500, "browsing/update"),
                        T.tcp_row("10.0.0.1", "10.0.0.9", 443, t - 30_000, 2500, "")],   # empty label
                   nocomplete=[T.tcp_row("10.0.0.1", "10.0.0.7", 22, t + 1000, 3, "service_scan", s_bytes=0)],
                   udp=[T.udp_row("10.0.0.1", "10.0.0.53", 53, t - 120_000, 0.25, "benign DNS"),
                        T.udp_row("10.0.0.2", "10.0.0.53", 53, t, 0.0, "data exfiltration", s_pkts=0)])
    flows = F.read_network_zip(z, "toy")
    table, unmapped = F.build_feature_table(flows, label_map)
    assert validate_feature_frame(table) == []
    assert unmapped.flow_id.tolist() == ["f-toy-tcp_complete-0000001"]
    r = table.set_index("flow_id")
    assert r.loc["f-toy-udp_complete-0000000", "duration_s"] == pytest.approx(0.251)  # UDP seconds kept as s
    assert r.loc["f-toy-tcp_complete-0000000", "duration_s"] == pytest.approx(0.5)    # TCP ms -> s
    assert r.loc["f-toy-udp_complete-0000000", "protocol"] == 17
    s = r.loc["f-toy-tcp_nocomplete-0000000"]
    # the scan's window: 3 earlier flows of 10.0.0.1 (the unlabeled one still counts as traffic)
    assert (s.win5_conn_count, s.win5_distinct_dst_ports, s.win5_dns_count) == (3, 3, 1)
    assert s.win5_dns_avg_bytes == 150 and s.label == 1 and s.protocol == 6
    assert (s.src_ip, s.dst_ip, s.src_port, s.dst_port) == ("10.0.0.1", "10.0.0.7", 40000, 22)
    assert s.start_time == "2022-01-15T00:15:01.000Z" and s.bytes == 100 and s.packets == 7


def test_non_numeric_values_fail_loudly(tmp_path):
    bad = T.tcp_row("10.0.0.1", "10.0.0.2", 80, T.T0, 5, "mail")
    bad["c_bytes_all"] = "-"
    with pytest.raises(ValueError, match="non-numeric"):
        F.read_network_zip(T.make_zip(tmp_path / "bad.zip", [bad], [], []), "bad")
