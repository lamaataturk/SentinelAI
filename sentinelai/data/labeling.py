"""
H-3: labeling rule - AIT Netflow labels -> label 0 (normal) / 1 (suspicious).

THE RULE (version 1.0)
  1. The only source of truth is the publisher's label_info.txt
     (Zenodo record 13168643, md5 e32c0e08d15725999df0c6a0c02aff47).
  2. A flow gets label = 0 if its label string is listed under
     "Benign labels in <its protocol>", and label = 1 if it is listed under
     "Malicious labels in <its protocol>".
  3. Matching is EXACT: no whitespace stripping, no case folding, and the
     protocol must match (a UDP-only label found in a TCP file is NOT mapped).
  4. Anything else (empty label, unknown string, label listed only for the other
     protocol) is UNMAPPED: label = <NA>. Unmapped flows are never treated as
     benign. They are left out of training/evaluation labels, but they are
     still real traffic, so the feature module keeps them when it computes the
     per-host time windows.
  5. Protocol comes from the file name: tcp_complete.csv / tcp_nocomplete.csv -> TCP,
     udp_complete.csv -> UDP (H-1 checked this against each file's schema).
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pandas as pd

RULE_VERSION = "1.0"
OFFICIAL_LABEL_INFO_MD5 = "e32c0e08d15725999df0c6a0c02aff47"
NORMAL, SUSPICIOUS = 0, 1
_SECTION = re.compile(r"(Benign|Malicious) labels in (TCP|UDP):")


def parse_label_info_text(text: str) -> dict[str, dict[str, int]]:
    """Parse label_info.txt text into {"TCP": {label: 0|1}, "UDP": {...}}.
    Raises if the four sections are not all present, if a label appears before
    the first section, or if a label is listed as both benign and malicious."""
    mapping: dict[str, dict[str, int]] = {"TCP": {}, "UDP": {}}
    sections, current = [], None
    for lineno, line in enumerate(text.splitlines(), 1):   # splitlines drops \r\n
        if line.strip() == "":
            continue
        m = _SECTION.fullmatch(line.strip())
        if m:
            current = (m.group(2), NORMAL if m.group(1) == "Benign" else SUSPICIOUS)
            sections.append(m.group(0))
            continue
        if current is None:
            raise ValueError(f"label_info.txt line {lineno}: label before any section: {line!r}")
        proto, y = current
        if mapping[proto].get(line, y) != y:
            raise ValueError(f"label_info.txt line {lineno}: {line!r} is both benign and malicious in {proto}")
        mapping[proto][line] = y
    if sorted(sections) != sorted({f"{k} labels in {p}:" for k in ("Benign", "Malicious") for p in ("TCP", "UDP")}):
        raise ValueError(f"expected the 4 sections, found {sections}")
    return mapping


def load_label_info(path: str | Path, check_md5: bool = True) -> dict[str, dict[str, int]]:
    raw = Path(path).read_bytes()
    if check_md5:
        actual = hashlib.md5(raw).hexdigest()
        if actual != OFFICIAL_LABEL_INFO_MD5:
            raise ValueError(f"label_info.txt md5 {actual} != official {OFFICIAL_LABEL_INFO_MD5}")
    return parse_label_info_text(raw.decode("utf-8-sig"))


def protocol_from_filename(name: str) -> str:
    base = Path(name).name.lower()
    if base.startswith("tcp"):
        return "TCP"
    if base.startswith("udp"):
        return "UDP"
    raise ValueError(f"cannot infer protocol from file name {name!r}")


def apply_rule(labels: pd.Series, protocol: str, mapping: dict[str, dict[str, int]]) -> pd.DataFrame:
    """Return a DataFrame with label (Int8, <NA> = unmapped) and label_status
    ('normal' / 'suspicious' / 'unmapped')."""
    if protocol not in mapping:
        raise ValueError(f"unknown protocol {protocol!r}")
    labels = labels.astype("string").fillna("")          # a real NaN label is unmapped, never benign
    y = labels.map(mapping[protocol]).astype("Int8")      # exact dict lookup
    status = pd.Series("unmapped", index=labels.index, dtype="string")
    status[y == NORMAL] = "normal"
    status[y == SUSPICIOUS] = "suspicious"
    return pd.DataFrame({"label": y, "label_status": status})
