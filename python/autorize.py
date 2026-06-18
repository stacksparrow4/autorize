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


def apply_rule(data: bytes, pattern: re.Pattern, repl: str) -> bytes:
    """Apply the regex match-and-replace to the request bytes."""
    text = data.decode("utf-8", "surrogateescape")
    text = pattern.sub(repl, text)
    return text.encode("utf-8", "surrogateescape")


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
    "red": "\033[31m",
    "magenta": "\033[35m",
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



class Table:
    COLUMNS = [
        ("ID", 10),
        ("Orig Status", 12),
        ("Orig Len", 10),
        ("Mod Status", 12),
        ("Mod Len", 10),
    ]

    def header(self) -> None:
        cells = [f"{name:<{width}}" for name, width in self.COLUMNS]
        line = " | ".join(cells)
        print(line)
        print("-" * len(line))
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


def process(req_path: Path, req_id: str, pattern: re.Pattern, repl: str,
            timeout: float, out_dir: Path, table: Table) -> None:
    req_bytes = read_stable(req_path)

    # Original response from the response file pwnproxy saved alongside it.
    resp_path = req_path.with_name(req_path.name + ".resp")
    if wait_for(resp_path, timeout):
        orig_status, orig_len = parse_response(read_stable(resp_path))
    else:
        orig_status, orig_len = "N/A", "N/A"

    # Modified response: re-send the request with the rule applied.
    modified = apply_rule(req_bytes, pattern, repl)
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

    table.row(req_id, orig_status, orig_len, mod_status, mod_len)



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
    )
    parser.add_argument("match", help="regex to match in each request")
    parser.add_argument("replace", help="replacement string (supports \\1 backrefs)")
    parser.add_argument("-d", "--history-dir", default="history",
                        help="directory pwnproxy writes .req files to (default: history)")
    args = parser.parse_args()

    timeout = _env_float("AUTORIZE_RESP_TIMEOUT", 15.0)
    interval = _env_float("AUTORIZE_SCAN_INTERVAL", 0.5)

    try:
        pattern = re.compile(args.match)
    except re.error as exc:
        sys.stderr.write(f"invalid match regex: {exc}\n")
        return 2

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
                    process(p, req_id, pattern, args.replace, timeout,
                            out_dir, table)
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
