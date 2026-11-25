"""H-3: the labeling rule (AIT label -> 0 normal / 1 suspicious)."""
import hashlib

import pandas as pd
import pytest

import ait_testdata as T
from sentinelai.data.labeling import (OFFICIAL_LABEL_INFO_MD5, apply_rule, load_label_info,
                                      parse_label_info_text, protocol_from_filename)


@pytest.fixture
def label_map():
    return parse_label_info_text(T.LABEL_INFO)


def test_fixture_is_the_official_file():
    assert hashlib.md5(T.LABEL_INFO.encode()).hexdigest() == OFFICIAL_LABEL_INFO_MD5


def test_section_sizes(label_map):
    count = lambda p, y: sum(v == y for v in label_map[p].values())
    assert (count("TCP", 0), count("TCP", 1), count("UDP", 0), count("UDP", 1)) == (13, 39, 12, 1)


def test_known_labels(label_map):
    s = pd.Series(["service_scan", "mail", "broken flow - benign", "dns_brute_force_start"])
    assert apply_rule(s, "TCP", label_map)["label"].tolist() == [1, 0, 0, 1]
    s = pd.Series(["data exfiltration", "benign DNS - attacker requesting updates", "NTP"])
    assert apply_rule(s, "UDP", label_map)["label"].tolist() == [1, 0, 0]


@pytest.mark.parametrize("value", ["", " mail", "mail ", "MAIL", "Service_scan", "unknown", "nan"])
def test_unmapped_is_never_benign(label_map, value):
    out = apply_rule(pd.Series([value]), "TCP", label_map)
    assert out["label"].isna().all() and (out["label_status"] == "unmapped").all()


def test_real_nan_is_unmapped(label_map):
    assert apply_rule(pd.Series([None, float("nan")], dtype=object), "TCP", label_map)["label"].isna().all()


def test_protocol_must_match(label_map):
    assert apply_rule(pd.Series(["data exfiltration"]), "TCP", label_map)["label"].isna().all()
    assert apply_rule(pd.Series(["DNS"]), "UDP", label_map)["label"].isna().all()   # 'DNS' is TCP-only


def test_protocol_from_filename():
    assert protocol_from_filename("tcp_complete.csv") == "TCP"
    assert protocol_from_filename("x/tcp_nocomplete.csv") == "TCP"
    assert protocol_from_filename("udp_complete.csv") == "UDP"
    with pytest.raises(ValueError):
        protocol_from_filename("flows.csv")


def test_bad_files_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        parse_label_info_text("Benign labels in TCP:\nmail\n")                  # sections missing
    with pytest.raises(ValueError):
        parse_label_info_text("mail\n" + T.LABEL_INFO)                          # label before section
    p = tmp_path / "label_info.txt"
    p.write_bytes(T.LABEL_INFO.encode() + b"x")
    with pytest.raises(ValueError):
        load_label_info(p)                                                       # md5 mismatch
