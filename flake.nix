{
  description = "GTK4 UI and command line for OpenSnitch";

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
      buildPackages = pkgs: [pkgs.gtk4 pkgs.libadwaita];
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
      # Icon themes, as $XDG_DATA_DIRS entries: GLib finds icons under
      # $XDG_DATA_DIRS/icons. The compiled gsettings catalogues need the same
      # treatment, but wrapGAppsHook4 already puts those on the path, so only
      # the themes are added by the wrapper below.
      iconDirs = pkgs:
        builtins.concatStringsSep ":" (
          map (p: "${p}/share") [ pkgs.adwaita-icon-theme pkgs.hicolor-icon-theme ]
        );
      # The package, so the flake can expose it as a package *and* through an
      # overlay for a NixOS system that wants `pkgs.opensnitch-ui-gtk4`.
      # The whole workspace is built, so one derivation ships both programs:
      # `bin/opensnitch-ui-gtk4` and `bin/opensnitch-cli`.
      package = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "opensnitch-ui-gtk4";
        version = "0.9.0";

        src = ./.;

        cargoLock = {
          lockFile = ./Cargo.lock;
          allowBuiltinFetchGit = true;
        };

        nativeBuildInputs = (nativePackages pkgs) ++ [ pkgs.wrapGAppsHook4 ];
        buildInputs = buildPackages pkgs;

        # `cli/` is a member of the workspace, and building only the root
        # package would ship the prompt alone. Both programs land in the same
        # `target/release`, and cargoInstallHook copies every executable it
        # finds there into `$out/bin`, so no install flags are needed.
        # The CLI pulls no GTK (tonic, prost, tokio only), so `--workspace`
        # adds no new system dependencies to this build.
        cargoBuildFlags = [ "--workspace" ];

        # A prompt started as a systemd user service inherits no session
        # environment, so it finds no icon theme for the program it asks about.
        # wrapGAppsHook4 covers the rest of what a bare service lacks: it
        # prefixes XDG_DATA_DIRS with the compiled gsettings catalogues of
        # gsettings-desktop-schemas and gtk4 (without them libadwaita answers
        # `g_settings_schema_source_lookup: assertion 'source != NULL' failed`),
        # and sets GDK_PIXBUF_MODULE_FILE and GIO_EXTRA_MODULES. It does not
        # touch icons, so those are the only entries added here.
        # Only the prompt is wrapped by hand: `opensnitch-cli` needs no GTK
        # environment, and a wrapper of its own would only get in the way of a
        # pipe. wrapGAppsHook4 wraps every program in `$out/bin`, so the CLI
        # does pick the same variables up; they set nothing it reads.
        postFixup = ''
          wrapProgram $out/bin/opensnitch-ui-gtk4 \
            --prefix XDG_DATA_DIRS ':' "${iconDirs pkgs}"
        '';

        meta = {
          description = "GTK4 UI and command line for OpenSnitch";
          homepage = "https://github.com/knoopx/opensnitch-ui-gtk4";
          license = pkgs.lib.licenses.mit;
          # `nix run` starts the prompt; `opensnitch-cli` is the other program
          # this package installs.
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
