# Wire MLS test tool

## Building with nix (on nixos)

Use the build environment defined in [wire-server](https://www.github.com/wireapp/wire-server) for building:

```sh
nix-shell -A mls_test_cli $WIRE_SERVER/nix/default.nix
# inside nix-shell
NIX_HARDENING_ENABLE="" cargo build
```
