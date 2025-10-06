{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    crane = {
      url = "github:ipetkov/crane";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          inherit (pkgs) lib;

          rustToolchain = pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          # When filtering sources, we want to allow assets other than .rs files
          src = lib.cleanSourceWith {
            src = ./.; # The original, unfiltered source
            filter = path: type:
              (lib.hasSuffix "\.toml" path) ||
              (lib.hasSuffix "\.md" path) ||
              (lib.hasInfix "/test" path) ||
              (lib.hasInfix "/tests/" path) ||

              # Default filter from crane (allow .rs files)
              (craneLib.filterCargoSources path type)
            ;
          };

          nativeBuildInputs = with pkgs; [ 
            rustToolchain 
          ]; # required only at build time
          
          buildInputs = with pkgs; [ 
          ] ++ lib.optionals pkgs.stdenv.isDarwin [
            # Additional darwin dependencies if needed
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          ]; # also required at runtime

          commonArgs = {
            inherit src buildInputs nativeBuildInputs;
            pname = "boltz-client";
            version = "0.3.0";
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          
          bin = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            cargoTestExtraArgs = "--lib"; # only unit testing, integration testing has more requirements
          });

        in
        {
          packages = {
            inherit bin;
            default = bin;
          };

          devShells.default = pkgs.mkShell {
            inputsFrom = [ bin ];

            buildInputs = with pkgs; [
              # Additional development tools
              cargo-watch
              cargo-edit
            ];

            # Environment variables for development
            RUST_LOG = "debug";

            BITCOIND_SKIP_DOWNLOAD = true;
            ELEMENTSD_SKIP_DOWNLOAD = true;

            BITCOIND_EXEC = "${pkgs.bitcoind}/bin/bitcoind";
            ELEMENTSD_EXEC = "${pkgs.elementsd}/bin/elementsd";

          };
        }
      );
} 
