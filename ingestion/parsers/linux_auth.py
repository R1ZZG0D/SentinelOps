"""Parser for Linux authentication telemetry from syslog (sshd + sudo).

These are the lines journald/auditd-backed syslog emits for SSH and privilege use:

    Jun 24 14:03:11 web01 sshd[2291]: Failed password for root from 203.0.113.7 port 51514 ssh2
    Jun 24 14:05:02 web01 sshd[2305]: Accepted password for deploy from 203.0.113.7 port 51600 ssh2
    Jun 24 14:10:00 web01 sudo[2400]:   deploy : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash

Syslog timestamps have no year, so the year is supplied (defaults to the current
year) when normalizing to ISO-8601.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from .normalize import build_event

SOURCE = "linux_auth"

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_SYSLOG_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\w+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_SSH_AUTH_RE = re.compile(
    r"(?P<action>Failed|Accepted) password for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SUDO_RE = re.compile(r"(?P<user>\S+)\s+:\s+.*COMMAND=(?P<cmd>.+)$")


def _to_iso(mon: str, day: str, time: str, year: int) -> str:
    month = _MONTHS.get(mon, 1)
    return f"{year:04d}-{month:02d}-{int(day):02d}T{time}Z"


def parse_line(line: str, year: Optional[int] = None) -> Optional[dict[str, Any]]:
    line = line.rstrip("\n")
    if not line.strip() or line.startswith("#"):
        return None
    if year is None:
        year = datetime.now().year

    m = _SYSLOG_RE.match(line)
    if not m:
        return None

    ts = _to_iso(m.group("mon"), m.group("day"), m.group("time"), year)
    proc = m.group("proc")
    msg = m.group("msg")
    host = m.group("host")

    if proc == "sshd":
        am = _SSH_AUTH_RE.search(msg)
        if not am:
            return None
        failed = am.group("action") == "Failed"
        return build_event(
            timestamp=ts,
            category="authentication",
            action="logon_failed" if failed else "logon",
            outcome="failure" if failed else "success",
            log_source=SOURCE,
            raw=line,
            source_ip=am.group("ip"),
            source_port=int(am.group("port")),
            user=am.group("user"),
            host=host,
            os_name="linux",
            network_proto="ssh",
            extra={"invalid_user": bool(am.group("invalid"))},
        )

    if proc == "sudo":
        sm = _SUDO_RE.search(msg)
        if not sm:
            return None
        return build_event(
            timestamp=ts,
            category="process",
            action="sudo_command",
            outcome="success",
            log_source=SOURCE,
            raw=line,
            user=sm.group("user"),
            host=host,
            os_name="linux",
            extra={"command": sm.group("cmd").strip()},
        )

    return None


def parse(lines, year: Optional[int] = None):
    """Yield normalized events for an iterable of raw log lines."""
    for line in lines:
        event = parse_line(line, year=year)
        if event is not None:
            yield event
