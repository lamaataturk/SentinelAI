"""R-1 tests: the AIT-ADS loader keeps the answers out of the agent's table."""
import pytest

from sentinelai.contracts.messages import validate_message
from sentinelai.investigation.ait_ads import load_alert_csv, load_phases, to_alert_messages


def test_loader_keeps_answers_out(tmp_path):
    p = tmp_path / "x_alerts.txt"
    p.write_text("time,name,ip,host,short,time_label,event_label\n"
                 "1642723347,Wazuh: ClamAV database update,172.19.130.4,mail,W-Sys-Cav,false_positive,-\n"
                 "1642724061,Suricata: Alert - ET POLICY APT,10.143.0.103,internal_share,S-Flw-Apt,wpscan,wpscan\n"
                 "1642724062,AMiner: New event type.,10.143.0.104,intranet_server,A-All-Evt,dirb,-\n")
    alerts, labels = load_alert_csv(p, "x")
    assert not any(c.startswith("eval_") or c in ("time_label", "event_label") for c in alerts.columns)
    assert list(alerts["ids_source"]) == ["wazuh", "suricata", "aminer"]
    assert alerts["host_ip"].notna().all()
    assert set(labels.columns) == {"alert_id", "eval_phase", "eval_event_label"}
    assert all(validate_message(m) == [] for m in to_alert_messages(alerts))


def test_phase_file_runs_only_when_allowed(tmp_path):
    marker = tmp_path / "ran.txt"
    (tmp_path / "attacktimes.py").write_text(
        "from datetime import datetime, timezone\n"
        f"open({str(marker)!r}, 'w').close()\n"
        "phase = {'fox': {'network_scans': (datetime(2022, 1, 18, 11, 0, tzinfo=timezone.utc),\n"
        "                                   datetime(2022, 1, 18, 11, 30, tzinfo=timezone.utc))}}\n",
        encoding="utf-8")
    with pytest.raises(PermissionError):
        load_phases(tmp_path)
    assert not marker.exists()

    phases = load_phases(tmp_path, allow_code_execution=True)
    assert marker.exists()
    assert phases.to_dict("records") == [{"scenario": "fox", "phase": "network_scans",
                                          "start": "2022-01-18T11:00:00Z", "end": "2022-01-18T11:30:00Z",
                                          "is_attack": True}]
    with pytest.raises(FileNotFoundError):
        load_phases(tmp_path / "missing", allow_code_execution=True)
