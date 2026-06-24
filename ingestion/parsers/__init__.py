"""Log parsers. Each module exposes SOURCE and parse_line(line) -> event|None."""

from . import windows_security, linux_auth, zeek_conn

# Registry: log-source name -> parser module.
PARSERS = {
    windows_security.SOURCE: windows_security,
    linux_auth.SOURCE: linux_auth,
    zeek_conn.SOURCE: zeek_conn,
}


def get_parser(source: str):
    """Return the parser module for a log-source name, or raise KeyError."""
    if source not in PARSERS:
        raise KeyError(
            f"unknown source {source!r}; known sources: {', '.join(sorted(PARSERS))}"
        )
    return PARSERS[source]
