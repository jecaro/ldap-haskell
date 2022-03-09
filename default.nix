{ pkgs ? import <nixos-unstable> {} }:
let drv = pkgs.haskellPackages.callCabal2nix "LDAP" ./. {};
in pkgs.haskell.lib.addExtraLibrary drv pkgs.cyrus_sasl
