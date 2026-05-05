{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils/v1.0.0";
  };

  # Custom colored bash prompt
  nixConfig.bash-prompt =
    "\\[\\e[0;32m\\][mcp-servers]\\[\\e[m\\] \\[\\e[38;5;244m\\]\\w\\[\\e[m\\] % ";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        devShells = flake-utils.lib.flattenTree {
          default = pkgs.mkShell (attrs: {
            nativeBuildInputs = [
              (pkgs.python3.withPackages (pp: [
                pp.uv
              ]))
              pkgs.python3Packages.venvShellHook
            ];
            venvDir = "./.venv";
            postVenvCreation = ''
              uv sync --active
            '';
          });
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
