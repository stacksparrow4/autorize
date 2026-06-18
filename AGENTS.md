# AGENTS.md

## Project overview

Autorize is a small tool that watches pwnproxy's `history/` directory and
replays newly captured HTTP requests with a regex match-and-replace applied,
comparing the original and modified responses side by side. It is useful for
spotting authorization differences at a glance.

The actual HTTP requests are performed via the `send-request` helper (the
`send-request` output of the [nvim-http-client](https://github.com/stacksparrow4/nvim-http-client)
flake).

## Layout

- `python/autorize.py` — the entire application; a pure-stdlib Python 3 script.
- `default.nix` — Nix package. Rewrites the `@send_request@` placeholder and the
  shebang at build time to absolute store paths.
- `flake.nix` — flake exposing the `autorize` package and app for all systems.
- `README.md` — user-facing documentation.

## Build & run

```bash
# Build the package
nix build

# Run via the flake app
nix run . -- match replace
```

## Checks

- There is no test suite; verify changes by running against a sample
  `history/` directory.
