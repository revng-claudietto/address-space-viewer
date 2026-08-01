{
  description = "Record how a process's address space evolves, and watch it";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forEach = f: nixpkgs.lib.genAttrs systems
        (system: f system nixpkgs.legacyPackages.${system});
    in
    {
      # One command, with subcommands: record, parse, summary, view, shot.
      packages = forEach (system: pkgs: rec {
        as-trace = pkgs.callPackage ./nix/as-trace.nix { };
        default = as-trace;
      });

      apps = forEach (system: pkgs: rec {
        as-trace = {
          type = "app";
          program = "${self.packages.${system}.as-trace}/bin/as-trace";
        };
        default = as-trace;
      });

      # `nix develop` adds what only the viewer's own checking needs: a
      # browser, and the bindings to drive it.  `as-trace shot` finds them
      # through PLAYWRIGHT_BROWSERS_PATH.
      devShells = forEach (system: pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (ps: [ ps.pyelftools ps.playwright ]))
            pkgs.strace
            pkgs.playwright-driver.browsers
          ];
          env = {
            PLAYWRIGHT_BROWSERS_PATH = "${pkgs.playwright-driver.browsers}";
            PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = "1";
          };
          shellHook = ''
            echo "as-trace: ./as-trace --help"
          '';
        };
      });

      checks = forEach (system: pkgs: {
        tests = self.packages.${system}.as-trace.tests;
      });
    };
}
