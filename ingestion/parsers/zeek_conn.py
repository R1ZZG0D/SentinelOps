"""Parser for Zeek conn.log (tab-separated network connection records).

Zeek emits a TSV with a `#fields` header declaring column order, e.g.:

    #fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service \
        duration orig_bytes resp_bytes conn_state
    1718900000.123  C1  10.0.0.5  51514  203.0.113.7  4444  tcp  -  0.5  120  300  S0

We honor the `#fields` header when present and fall back to the default column
order otherwise, then normalize the 5-tuple to the common schema.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

SOURCE = "zeek_conn"

DEFAULT_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
]


def _epoch_to_iso(ts: str) -> str:
    dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_to_event(row: dict[str, str], raw: str) -> dict[str, Any]:
    # Import here to keep the module importable even if normalize moves.
    from .normalize import build_event

    def num(v: Optional[str]) -> Optional[int]:
        if v is None or v in ("-", ""):
            return None
        try:
            return int(float(v))
        except ValueError:
            return None

    conn_state = row.get("conn_state", "-")
    # S0 = connection attempt seen, no reply (typical of scans/unreachable).
    outcome = "failure" if conn_state in ("S0", "REJ", "RSTO") else "success"

    return build_event(
        timestamp=_epoch_to_iso(row["ts"]),
        category="network",
        action="network_flow",
        outcome=outcome,
        log_source=SOURCE,
        raw=raw,
        source_ip=row.get("id.orig_h"),
        source_port=num(row.get("id.orig_p")),
        dest_ip=row.get("id.resp_h"),
        dest_port=num(row.get("id.resp_p")),
        network_proto=row.get("proto"),
        extra={
            "service": row.get("service"),
            "conn_state": conn_state,
            "orig_bytes": num(row.get("orig_bytes")),
            "resp_bytes": num(row.get("resp_bytes")),
            "uid": row.get("uid"),
        },
    )


def parse_line(line: str, fields: Optional[list[str]] = None) -> Optional[dict[str, Any]]:
    raw = line.rstrip("\n")
    if not raw.strip() or raw.startswith("#"):
        return None
    cols = raw.split("\t")
    names = fields or DEFAULT_FIELDS
    if len(cols) < len(names):
        return None
    row = dict(zip(names, cols))
    if "ts" not in row or "id.orig_h" not in row:
        return None
    return _row_to_event(row, raw)


def parse(lines):
    """Yield normalized events, honoring a `#fields` header if present."""
    fields = DEFAULT_FIELDS
    for line in lines:
        stripped = line.rstrip("\n")
        if stripped.startswith("#fields"):
            fields = stripped.split("\t")[1:]
            continue
        event = parse_line(stripped, fields=fields)
        if event is not None:
            yield event
