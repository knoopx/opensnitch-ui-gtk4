# opensnitch-ui-gtk4

A GTK4 UI for [OpenSnitch](https://github.com/evilsocket/opensnitch)

## Features

**Connection Dialog** — the program that is asking, its path and arguments, and
the destination: host, address, port, protocol. Allow, Drop or Reject. How long
the answer stands: once, 30 seconds, 5, 15 or 30 minutes, 1 or 12 hours, until
reboot, forever. What it covers: program path, command line, process id,
checksum, user id, destination IP, host, port, network. Extra conditions that
must all match. The process tree and environment. A countdown to the default
action, and a notification when the default wins.

**Rule editor** — name, description, enabled, checked before other rules, left
out of the log, action, duration, and condition rows: field, is / matches / in
network, value.

**Rule list** — every rule the daemon has: enabled, name, description, action,
duration, conditions, creation date. Search, filter to permanent or temporary,
sorting by column, an on/off switch, duplicate, edit, delete with undo, reload,
and the shortcut list.

**Panel icon** — the firewall's state: filtering, paused, or offline. The rule
list, and quit.

**Pause switch** — on and off, with the system's authorisation.

**Defaults** — taken from the Qt UI's settings file,
`~/.config/opensnitch/settings.conf`.

## Install

Only one UI can be connected to the daemon at a time, so the Qt UI must be off.

```nix
# flake inputs
inputs.opensnitch-ui-gtk4.url = "github:knoopx/opensnitch-ui-gtk4";
```

```nix
# NixOS system configuration
nixpkgs.overlays = [ inputs.opensnitch-ui-gtk4.overlays.default ];

systemd.user.services.opensnitch-ui-gtk4 = {
  Unit.Description = "opensnitch-ui-gtk4 - GTK4 UI for OpenSnitch";
  Unit.PartOf = [ "graphical-session.target" ];
  Unit.After = [ "graphical-session.target" ];
  Service.ExecStart = "${pkgs.opensnitch-ui-gtk4}/bin/opensnitch-ui-gtk4";
  Service.Restart = "on-failure";
  Install.WantedBy = [ "graphical-session.target" ];
};
```

## Development

```sh
nix develop                 # rust, gtk4, libadwaita, gtk4-layer-shell, protoc
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
nix build .#default         # the package
```
