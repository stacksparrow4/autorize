#!/usr/bin/env python3
"""Autorize: replay captured pwnproxy requests with a match-and-replace rule.

pwnproxy (a mitmproxy fork) writes every intercepted HTTP request/response to a
``history/`` directory in the current working directory as numbered files:

    history/000001.req        - the raw request, prefixed with a ``---`` block
    history/000001.req.resp   - the raw response (body decoded)

Autorize watches that directory. Whenever a new ``.req`` file appears it:

  1. reads the original response from the matching ``.req.resp`` file,
  2. applies the configured regex match-and-replace to the request,
  3. re-sends the modified request via the ``send-request`` helper (the
     ``send-request`` output of the nvim-http-client flake),
  4. prints a table row comparing the original and modified responses.

The ``.req`` file format is exactly what ``send-request`` reads on stdin, so the
(modified) file contents are piped straight through.
"""

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# Path to the send-request executable. Replaced at Nix build time with the
# absolute store path of the flake's send-request output. Falls back to looking
# the binary up on PATH when run from a source checkout.
SEND_REQUEST = "@send_request@"
if SEND_REQUEST.startswith("@"):
    SEND_REQUEST = "send-request"

REQ_RE = re.compile(r"^(\d+)\.req$")


def split_head_body(data: bytes) -> tuple[bytes, bytes]:
    """Split an HTTP message into (head, body), tolerating CRLF or LF blanks."""
    i = data.find(b"\r\n\r\n")
    j = data.find(b"\n\n")
    if i != -1 and (j == -1 or i < j):
        return data[:i], data[i + 4:]
    if j != -1:
        return data[:j], data[j + 2:]
    return data, b""


def parse_response(data: bytes) -> tuple[str, int]:
    """Return (status code, body length) for a raw HTTP response."""
    head, body = split_head_body(data)
    first_line = head.split(b"\n", 1)[0].strip()
    parts = first_line.split()
    status = parts[1].decode("ascii", "replace") if len(parts) >= 2 else "?"
    return status, len(body)


def parse_request_path(data: bytes) -> str:
    """Return the request-target (path) from a raw HTTP request line."""
    head, _ = split_head_body(data)
    first_line = head.split(b"\n", 1)[0].strip()
    parts = first_line.split()
    return parts[1].decode("ascii", "replace") if len(parts) >= 2 else "?"


def apply_rules(data: bytes,
                rules: list[tuple[re.Pattern, str]]) -> tuple[bytes, int]:
    """Apply each (regex, replacement) rule to the request bytes in order.

    Returns the (possibly unchanged) bytes and the total number of
    substitutions made across all rules.
    """
    text = data.decode("utf-8", "surrogateescape")
    total = 0
    for pattern, repl in rules:
        text, count = pattern.subn(repl, text)
        total += count
    return text.encode("utf-8", "surrogateescape"), total


def send_request(req_bytes: bytes) -> tuple[bytes | None, str | None]:
    """Send a req document via the send-request helper. Returns (response, error)."""
    try:
        proc = subprocess.run(
            [SEND_REQUEST],
            input=req_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        return None, str(exc)
    if proc.returncode != 0:
        return None, proc.stderr.decode("utf-8", "replace").strip() or "send-request failed"
    return proc.stdout, None


def wait_for(path: Path, timeout: float) -> bool:
    """Wait up to ``timeout`` seconds for ``path`` to exist."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.1)
    return path.exists()


def read_stable(path: Path, settle: float = 0.2, timeout: float = 10.0) -> bytes:
    """Read ``path`` once it is non-empty and its size has stopped growing.

    Guards against reading a file that has only just been created (and is still
    being written): a transient zero-byte file is never treated as "final",
    since every valid .req/.resp message has at least a request/status line.
    """
    last = -1
    deadline = time.monotonic() + timeout
    while True:
        try:
            size = path.stat().st_size
        except OSError:
            time.sleep(settle)
            continue
        if size > 0 and size == last:
            break
        if time.monotonic() > deadline:
            break
        last = size
        time.sleep(settle)
    return path.read_bytes()


USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

RESET = "\033[0m"
COLORS = {
    "green": "\033[32m",
    "cyan": "\033[36m",
    "yellow": "\033[33m",
    "orange": "\033[38;5;208m",
    "red": "\033[31m",
    "magenta": "\033[35m",
    "grey": "\033[90m",
}


def status_color(status: str) -> str:
    """Pick an ANSI color name for an HTTP status string."""
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "magenta"  # N/A, ERR, ?, etc.
    if 200 <= code < 300:
        return "green"
    if 300 <= code < 400:
        return "cyan"
    if 400 <= code < 500:
        return "yellow"
    if 500 <= code < 600:
        return "red"
    return "magenta"


def colorize(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    return f"{COLORS[color]}{text}{RESET}"


def apply_rules_highlight(data: bytes,
                          rules: list[tuple[re.Pattern, str]]) -> tuple[str, int]:
    """Like apply_rules, but colour each replacement (orange) in the result."""
    text = data.decode("utf-8", "surrogateescape")
    total = 0
    for pattern, repl in rules:
        def _sub(m, repl=repl):
            return colorize(m.expand(repl), "orange")
        text, count = pattern.subn(_sub, text)
        total += count
    return text, total



class Table:
    COLUMNS = [
        ("ID", 10),
        ("Orig Status", 12),
        ("Orig Len", 10),
        ("Mod Status", 12),
        ("Mod Len", 10),
        ("Path", 20),
    ]

    def header(self) -> None:
        cells = [f"{name:<{width}}" for name, width in self.COLUMNS]
        line = " | ".join(cells)
        print(line)
        print(colorize("-" * len(line), "grey"))
        sys.stdout.flush()

    STATUS_COLUMNS = {1, 3}

    def row(self, *values) -> None:
        cells = []
        for idx, (value, (_, width)) in enumerate(zip(values, self.COLUMNS)):
            cell = f"{str(value):<{width}}"
            if idx in self.STATUS_COLUMNS:
                cell = colorize(cell, status_color(str(value)))
            cells.append(cell)
        print(" | ".join(cells))
        sys.stdout.flush()

    def warning(self, req_id: str, message: str) -> None:
        id_width = self.COLUMNS[0][1]
        cell = f"{str(req_id):<{id_width}}"
        print(f"{cell} | {colorize(message, 'yellow')}")
        sys.stdout.flush()


def process(req_path: Path, req_id: str, filters: list[re.Pattern],
            invert_filters: list[re.Pattern],
            rules: list[tuple[re.Pattern, str]], timeout: float,
            out_dir: Path, table: Table) -> None:
    req_bytes = read_stable(req_path)

    # Filter: when filter regexes are set, only handle requests matching at
    # least one of them; always ignore requests matching an inverse filter.
    if filters or invert_filters:
        text = req_bytes.decode("utf-8", "surrogateescape")
        if filters and not any(f.search(text) for f in filters):
            return
        if any(f.search(text) for f in invert_filters):
            return

    # Apply each rule in order. If nothing matched, the request would be
    # unchanged, so there is no point re-sending it: warn instead.
    modified, count = apply_rules(req_bytes, rules)
    if count == 0:
        table.warning(req_id, "no-match: request unchanged, not resent")
        return

    # Original response from the response file pwnproxy saved alongside it.
    resp_path = req_path.with_name(req_path.name + ".resp")
    if wait_for(resp_path, timeout):
        orig_status, orig_len = parse_response(read_stable(resp_path))
    else:
        orig_status, orig_len = "N/A", "N/A"

    # Modified response: re-send the request with the rule applied.
    resp, err = send_request(modified)
    if err is not None:
        mod_status, mod_len = "ERR", err
    else:
        mod_status, mod_len = parse_response(resp)

    # Save the modified request and its response alongside in the output dir.
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{req_id}.modified.req").write_bytes(modified)
    if resp is not None:
        (out_dir / f"{req_id}.modified.req.resp").write_bytes(resp)

    path = parse_request_path(req_bytes)
    table.row(req_id, orig_status, orig_len, mod_status, mod_len, path)


def highlight_matches(text: str, patterns: list[re.Pattern],
                      color: str) -> str:
    """Return text with every match of any pattern coloured."""
    spans = []
    for p in patterns:
        for m in p.finditer(text):
            if m.start() != m.end():
                spans.append((m.start(), m.end()))
    if not spans:
        return text
    spans.sort()
    merged = [spans[0]]
    for start, end in spans[1:]:
        if start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    out = []
    last = 0
    for start, end in merged:
        out.append(text[last:start])
        out.append(colorize(text[start:end], color))
        last = end
    out.append(text[last:])
    return "".join(out)


def _show(content: str) -> None:
    print(colorize("-" * 60, "grey"))
    sys.stdout.write(content)
    if not content.endswith("\n"):
        sys.stdout.write("\n")
    print(colorize("-" * 60, "grey"))


def test_request(path: Path, filters: list[re.Pattern],
                 invert_filters: list[re.Pattern],
                 rules: list[tuple[re.Pattern, str]]) -> int:
    """Dry-run a single .req file: report filtering and show the diff.

    Sends nothing and writes nothing; purely for testing rules.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        sys.stderr.write(f"cannot read {path}: {exc}\n")
        return 2

    text = data.decode("utf-8", "surrogateescape")

    # Doesn't match any normal filter: ignored, shown plain.
    if filters and not any(f.search(text) for f in filters):
        print(colorize("IGNORED", "red") +
              ": request matches none of the -f filters")
        _show(text)
        return 0

    # Matches an inverse filter: ignored, with the inverse match highlighted.
    matched_inv = [f for f in invert_filters if f.search(text)]
    if matched_inv:
        names = ", ".join(repr(f.pattern) for f in matched_inv)
        print(colorize("IGNORED", "red") +
              f": request matches inverse filter(s) {names}")
        _show(highlight_matches(text, matched_inv, "red"))
        return 0

    # Passes the filters: show the filter matches, then the changes.
    print(colorize("PASSES", "green") + ": request would be handled")

    if filters:
        _show(highlight_matches(text, filters, "green"))

    highlighted, count = apply_rules_highlight(data, rules)
    if count == 0:
        print(colorize("no-match", "yellow") +
              ": request would be unchanged (not resent)")
        return 0

    _show(highlighted)
    return 0


def _env_float(name: str, default: float) -> float:
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return float(val)
    except ValueError:
        sys.stderr.write(f"invalid {name}={val!r}, using default {default}\n")
        return default


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay pwnproxy requests with a regex match-and-replace, "
                    "comparing original vs. modified responses.",
        epilog="-i makes every filter and match regex case insensitive.\n"
               "To affect only a single regex, use an inline flag in that\n"
               "pattern instead:\n"
               "  (?i)...     make the whole pattern case insensitive\n"
               "  (?i:...)    make just the enclosed part case insensitive",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("rules", nargs="+", metavar="match replace",
                        help="one or more match/replace pairs: each match is a "
                             "regex and each replace is its replacement string "
                             "(supports \\1 backrefs). Provide an even number "
                             "of arguments")
    parser.add_argument("-d", "--history-dir", default="history",
                        help="directory pwnproxy writes .req files to (default: history)")
    parser.add_argument("-f", "--filter", action="append", default=None,
                        metavar="FILTER",
                        help="regex a request must match to be handled; may be "
                             "given multiple times (a request is handled if it "
                             "matches any filter). Default: handle all requests")
    parser.add_argument("-v", "--invert-filter", action="append", default=None,
                        metavar="FILTER", dest="invert_filter",
                        help="inverse filter: a request matching this regex is "
                             "ignored. May be given multiple times (a request "
                             "is ignored if it matches any inverse filter)")
    parser.add_argument("-t", "--test", metavar="REQ_FILE", default=None,
                        help="test mode: read REQ_FILE, report whether it "
                             "passes the filters and show the would-be "
                             "modified request (changes highlighted). Sends "
                             "no requests and writes no files")
    parser.add_argument("-i", "--ignore-case", action="store_true",
                        help="make the filter and match regexes case insensitive")
    args = parser.parse_args()

    timeout = _env_float("AUTORIZE_RESP_TIMEOUT", 15.0)
    interval = _env_float("AUTORIZE_SCAN_INTERVAL", 0.5)

    flags = re.IGNORECASE if args.ignore_case else 0

    if len(args.rules) % 2 != 0:
        sys.stderr.write("match/replace arguments must come in pairs "
                         f"(got {len(args.rules)} values)\n")
        return 2

    filters: list[re.Pattern] = []
    for f in (args.filter or []):
        try:
            filters.append(re.compile(f, flags))
        except re.error as exc:
            sys.stderr.write(f"invalid filter regex {f!r}: {exc}\n")
            return 2

    invert_filters: list[re.Pattern] = []
    for f in (args.invert_filter or []):
        try:
            invert_filters.append(re.compile(f, flags))
        except re.error as exc:
            sys.stderr.write(f"invalid inverse filter regex {f!r}: {exc}\n")
            return 2

    rules: list[tuple[re.Pattern, str]] = []
    for match, repl in zip(args.rules[0::2], args.rules[1::2]):
        try:
            rules.append((re.compile(match, flags), repl))
        except re.error as exc:
            sys.stderr.write(f"invalid match regex {match!r}: {exc}\n")
            return 2

    if args.test is not None:
        return test_request(Path(args.test), filters, invert_filters, rules)

    history = Path(args.history_dir)
    out_dir = history.parent / "autorize"
    table = Table()
    table.header()

    seen: set[str] = set()
    if history.is_dir():
        seen = {p.name for p in history.iterdir() if REQ_RE.match(p.name)}

    try:
        while True:
            if history.is_dir():
                entries = sorted(
                    (p for p in history.iterdir() if REQ_RE.match(p.name)),
                    key=lambda p: p.name,
                )
                for p in entries:
                    if p.name in seen:
                        continue
                    seen.add(p.name)
                    req_id = REQ_RE.match(p.name).group(1)
                    process(p, req_id, filters, invert_filters, rules,
                            timeout, out_dir, table)
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
