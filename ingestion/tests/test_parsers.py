"""Unit tests for the SentinelOps log parsers.

Run from the repo root:  python3 -m pytest ingestion/tests -q
"""

import os

import pytest

from ingestion.parsers import get_parser, windows_security, linux_auth, zeek_conn

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "sample_logs")


def _read(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.readlines()


# --- Windows ---------------------------------------------------------------

def test_windows_failed_logon():
    line = ("2026-06-24T14:03:11Z host=WIN-DC01 EventID=4625 "
            "TargetUserName=administrator IpAddress=203.0.113.7 LogonType=3 Status=0xC000006A")
    e = windows_security.parse_line(line)
    assert e["event"] == {"category": "authentication", "action": "logon_failed", "outcome": "failure"}
    assert e["source"]["ip"] == "203.0.113.7"
    assert e["user"]["name"] == "administrator"
    assert e["host"]["name"] == "WIN-DC01"
    assert e["extra"]["logon_type"] == "3"


def test_windows_process_creation():
    line = ("2026-06-24T14:06:10Z host=WIN-DC01 EventID=4688 SubjectUserName=administrator "
            r"NewProcessName=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    e = windows_security.parse_line(line)
    assert e["event"]["category"] == "process"
    assert e["extra"]["event_id"] == 4688
    assert e["extra"]["process_name"].endswith("powershell.exe")


def test_windows_comment_and_blank_skipped():
    assert windows_security.parse_line("# a comment") is None
    assert windows_security.parse_line("") is None


# --- Linux -----------------------------------------------------------------

def test_linux_failed_password():
    line = "Jun 24 14:03:11 web01 sshd[2291]: Failed password for root from 203.0.113.7 port 51514 ssh2"
    e = linux_auth.parse_line(line, year=2026)
    assert e["@timestamp"] == "2026-06-24T14:03:11Z"
    assert e["event"]["outcome"] == "failure"
    assert e["source"]["ip"] == "203.0.113.7"
    assert e["source"]["port"] == 51514
    assert e["user"]["name"] == "root"
    assert e["extra"]["invalid_user"] is False


def test_linux_invalid_user_flagged():
    line = "Jun 24 14:03:15 web01 sshd[2293]: Failed password for invalid user admin from 203.0.113.7 port 51526 ssh2"
    e = linux_auth.parse_line(line, year=2026)
    assert e["user"]["name"] == "admin"
    assert e["extra"]["invalid_user"] is True


def test_linux_accepted_password():
    line = "Jun 24 14:03:45 web01 sshd[2305]: Accepted password for root from 203.0.113.7 port 51600 ssh2"
    e = linux_auth.parse_line(line, year=2026)
    assert e["event"]["action"] == "logon"
    assert e["event"]["outcome"] == "success"


def test_linux_sudo_command():
    line = "Jun 24 14:10:00 web01 sudo[2400]:   root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash /tmp/x.sh"
    e = linux_auth.parse_line(line, year=2026)
    assert e["event"]["action"] == "sudo_command"
    assert e["extra"]["command"] == "/bin/bash /tmp/x.sh"


# --- Zeek ------------------------------------------------------------------

def test_zeek_scan_is_failure():
    line = "1782655380.110\tCScan01\t203.0.113.7\t51514\t10.0.0.5\t22\ttcp\t-\t0.001\t0\t0\tS0"
    e = zeek_conn.parse_line(line)
    assert e["event"]["category"] == "network"
    assert e["event"]["outcome"] == "failure"          # S0 = no response
    assert e["destination"]["port"] == 22
    assert e["network"]["transport"] == "tcp"


def test_zeek_established_is_success():
    line = "1782655500.000\tCBeacon1\t10.0.0.5\t44120\t203.0.113.7\t4444\ttcp\t-\t60.0\t120\t300\tSF"
    e = zeek_conn.parse_line(line)
    assert e["event"]["outcome"] == "success"
    assert e["destination"]["ip"] == "203.0.113.7"
    assert e["destination"]["port"] == 4444


# --- Registry + end-to-end on the sample files -----------------------------

def test_registry_unknown_source():
    with pytest.raises(KeyError):
        get_parser("not_a_source")


@pytest.mark.parametrize(
    "source, filename, min_events",
    [
        ("windows_security", "windows_security.log", 10),
        ("linux_auth", "linux_auth.log", 11),
        ("zeek_conn", "zeek_conn.log", 10),
    ],
)
def test_full_file_parses(source, filename, min_events):
    parser = get_parser(source)
    events = list(parser.parse(_read(filename)))
    assert len(events) >= min_events
    for e in events:
        assert e["@timestamp"]
        assert e["log"]["source"] == source
        assert "raw" in e
