"""CLI: normalize a raw log file into newline-delimited JSON events.

    python3 -m ingestion.parsers.cli ingestion/sample_logs/linux_auth.log --source linux_auth

The output (NDJSON) is exactly the shape detections and the triage assistant
consume, and is what you would ship into the SIEM's ingest pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import get_parser, PARSERS


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Normalize raw logs to NDJSON events.")
    ap.add_argument("logfile", help="path to the raw log file ('-' for stdin)")
    ap.add_argument(
        "--source",
        required=True,
        choices=sorted(PARSERS),
        help="log source / parser to use",
    )
    ap.add_argument("--pretty", action="store_true", help="pretty-print each event")
    args = ap.parse_args(argv)

    parser = get_parser(args.source)
    stream = sys.stdin if args.logfile == "-" else open(args.logfile, encoding="utf-8")
    count = 0
    try:
        for event in parser.parse(stream):
            indent = 2 if args.pretty else None
            print(json.dumps(event, indent=indent))
            count += 1
    finally:
        if stream is not sys.stdin:
            stream.close()

    print(f"# normalized {count} event(s) from {args.source}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
