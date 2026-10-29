{
  description = "GTK4 UI for OpenSnitch";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # Libraries the prompt links against, and the tools its build needs. The
      # package and the dev shell share these lists, so `cargo build` inside
      # `nix develop` sees exactly what the package build sees.
      buildPackages = pkgs: [
        pkgs.gtk4
        pkgs.libadwaita
        pkgs.gtk4-layer-shell
      ];
      nativePackages = pkgs: [
        pkgs.pkg-config
        pkgs.protobuf
        # Cargo.lock pulls one crate over git.
        pkgs.git
      ];
      # Icon themes and gsettings schemas: without them a prompt started with
      # `cargo run` finds no icon for the program it asks about.
      runtimePackages = pkgs: [
        pkgs.adwaita-icon-theme
        pkgs.hicolor-icon-theme
        pkgs.gsettings-desktop-schemas
      ];
      # The package, so the flake can expose it as a package *and* through an
      # overlay for a NixOS system that wants `pkgs.opensnitch-ui-gtk4`.
      package = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "opensnitch-ui-gtk4";
        version = "0.9.0";

        src = ./.;

        cargoLock = {
          lockFile = ./Cargo.lock;
          allowBuiltinFetchGit = true;
        };

        nativeBuildInputs = nativePackages pkgs;
        buildInputs = buildPackages pkgs;

        meta = {
          description = "GTK4 UI for OpenSnitch";
          homepage = "https://github.com/jeronimoalbi/snitch";
          license = pkgs.lib.licenses.mit;
          mainProgram = "opensnitch-ui-gtk4";
        };
      };
    in
    {
      packages = forAllSystems (pkgs: {
        default = package pkgs;
      });

      # For a NixOS system that wants the program in `pkgs`.
      overlays.default = final: _previous: {
        opensnitch-ui-gtk4 = package final;
      };

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages =
            (nativePackages pkgs)
            ++ (buildPackages pkgs)
            ++ (runtimePackages pkgs)
            ++ [
              pkgs.cargo
              pkgs.clippy
              pkgs.rustc
              pkgs.rustfmt
              pkgs.rust-analyzer
            ];
        };
      });
    };
}
