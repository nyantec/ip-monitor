{
  description = "ip-monitor";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";

  outputs = { self, nixpkgs }: let
    overlay = final: prev: {
      ip-monitor = final.callPackage (
        { rustPlatform }:

        rustPlatform.buildRustPackage {
          pname = "ip-monitor";
          version = self.shortRev or "dirty-${toString self.lastModifiedDate}";
          src = self;
          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes = {
              "pnet-0.28.0" = "sha256-wWhidrz4tnwUQlDM/ajKZZiVGHJLo4zFb+9w7UFiUZA=";
            };
          };
          doCheck = false;
        }
      ) {};
    };
  in {
    inherit overlay;
    packages.x86_64-linux = import nixpkgs {
      system = "x86_64-linux";
      overlays = [ overlay ];
    };
    defaultPackage.x86_64-linux = self.packages.x86_64-linux.ip-monitor;
  };
}
