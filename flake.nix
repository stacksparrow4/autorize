{
  description = "Autorize - replay pwnproxy requests with a match-and-replace rule";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    nvim-http-client.url = "github:stacksparrow4/nvim-http-client";
  };

  outputs = { self, nixpkgs, nvim-http-client, ... }:
    let
      systems = nixpkgs.lib.systems.flakeExposed;
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          send-request = nvim-http-client.packages.${system}.send-request;
        in
        rec {
          autorize = import ./default.nix { inherit pkgs send-request; };
          default = autorize;
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.autorize}/bin/autorize";
        };
      });
    };
}
