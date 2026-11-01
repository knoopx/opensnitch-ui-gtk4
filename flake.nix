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

        # A prompt started as a systemd user service inherits no session
        # environment, so it finds no icon theme for the program it asks about.
        # wrapGAppsHook4 covers the rest of what a bare service lacks: it
        # prefixes XDG_DATA_DIRS with the compiled gsettings catalogues of
        # gsettings-desktop-schemas and gtk4 (without them libadwaita answers
        # `g_settings_schema_source_lookup: assertion 'source != NULL' failed`),
        # and sets GDK_PIXBUF_MODULE_FILE and GIO_EXTRA_MODULES. It does not
        # touch icons, so those are the only entries added here.
        postFixup = ''
          wrapProgram $out/bin/opensnitch-ui-gtk4 \
            --prefix XDG_DATA_DIRS ':' "${iconDirs pkgs}"
        '';

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
