# Nix package for autorize.
#
# autorize is a pure-stdlib Python script that watches pwnproxy's history/
# directory and replays new requests with a regex match-and-replace, using the
# `send-request` helper (the send-request output of the nvim-http-client flake)
# to actually perform the HTTP requests.
#
# The script's `@send_request@` placeholder is rewritten at build time to the
# absolute store path of that helper, so autorize has no runtime dependency on
# PATH or network access beyond send-request itself.
{
  pkgs ? import <nixpkgs> { },
  python3 ? pkgs.python3,
  send-request,
}:

pkgs.stdenv.mkDerivation {
  pname = "autorize";
  version = "0.1.0";

  src = ./python;

  dontBuild = true;
  doCheck = false;

  nativeBuildInputs = [ pkgs.makeWrapper ];

  installPhase = ''
    runHook preInstall

    install -D autorize.py $out/bin/autorize

    substituteInPlace $out/bin/autorize \
      --replace-fail '#!/usr/bin/env python3' '#!${python3}/bin/python3' \
      --replace-fail '@send_request@' '${send-request}/bin/send-request'

    runHook postInstall
  '';
}
