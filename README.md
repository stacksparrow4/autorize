# autorize

`autorize` is a small authorization-testing helper for
[`pwnproxy`](https://github.com/stacksparrow4/pwnproxy). It watches the
`history/` directory that pwnproxy writes intercepted traffic to and, for every
new request, replays a **modified** copy of that request (via a regex
match-and-replace) so you can spot authorization differences at a glance.

It is the same idea as Burp Suite's *Autorize* extension: take a real request,
swap out (for example) a session cookie or auth token, replay it, and compare
the response to the original.

## How it works

pwnproxy's `RawSave` addon saves each flow to the working directory:

```
history/000001.req        # raw request, prefixed with a `---` metadata block
history/000001.req.resp   # raw response, body decoded, Content-Length fixed
```

The `.req` format is exactly what the `send-request` helper (an output of the
[`nvim-http-client`](https://github.com/stacksparrow4/nvim-http-client) flake)
reads on stdin. autorize therefore:

1. waits for a new `history/NNNNNN.req` file to appear,
2. reads the original response from `history/NNNNNN.req.resp`,
3. applies the configured regex match-and-replace to the request,
4. pipes the modified request into `send-request`,
5. prints a table row comparing original vs. modified responses.

## Usage

```console
$ nix run github:stacksparrow4/autorize -- '<match-regex>' '<replacement>'
```

or from a checkout:

```console
$ nix build
$ ./result/bin/autorize '<match-regex>' '<replacement>'
```

Run it in a separate terminal from the same working directory in which
pwnproxy is running (so they share the `history/` folder).

### Example

Replace any session cookie with an attacker-controlled value to test for
broken access control:

```console
$ autorize 'session=[a-f0-9]+' 'session=attacker-token'
ID         | Orig Status  | Orig Len   | Mod Status   | Mod Len
-----------------------------------------------------------------
000001     | 200          | 5123       | 403          | 28
000002     | 200          | 812        | 200          | 812
```

The replacement string supports backreferences (`\1`, `\2`, ...).

### Options

```
autorize [-d HISTORY_DIR] [-t TIMEOUT] [-i INTERVAL] [-a] match replace

  match              regex to match in each request
  replace            replacement string (supports \1 backrefs)
  -d, --history-dir  directory pwnproxy writes .req files to (default: history)
  -t, --timeout      seconds to wait for the original .resp file (default: 15)
  -i, --interval     polling interval in seconds (default: 0.5)
  -a, --all          also process .req files already present at startup
```

## Table columns

| Column      | Meaning                                            |
| ----------- | -------------------------------------------------- |
| ID          | the zero-padded request number (e.g. `000001`)     |
| Orig Status | HTTP status of the original (captured) response    |
| Orig Len    | body length of the original response               |
| Mod Status  | HTTP status of the replayed, modified response     |
| Mod Len     | body length of the modified response               |

## Building

autorize is packaged as a Nix flake with `nvim-http-client` as an input (it
uses that flake's `send-request` output to perform requests):

```console
$ nix build           # builds .#autorize
$ nix run             # runs autorize
```
