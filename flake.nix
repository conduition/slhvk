{
  description = "SLH-DSA Vulkan (slhvk) with benches and dev shell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      perSystem = system:
        let
          pkgs = import nixpkgs { inherit system; };
          # CPU Vulkan ICD for deterministic CI/test runs.
          lvpIcd =
            if pkgs.stdenv.isx86_64
            then "${pkgs.mesa}/share/vulkan/icd.d/lvp_icd.x86_64.json"
            else "${pkgs.mesa}/share/vulkan/icd.d/lvp_icd.aarch64.json";

          nativeInputs = [
            pkgs.gnumake
            pkgs.glslang           # glslangValidator / glslc
            pkgs.xxd               # shader header generation
            pkgs.python3           # for download_test_vectors.py during tests
          ];

          buildInputs = [
            pkgs.vulkan-headers
            pkgs.vulkan-loader
          ];
        in { inherit pkgs lvpIcd nativeInputs buildInputs; };
    in {
      packages = forAllSystems (system:
        let
          cfg = perSystem system;
          inherit (cfg) pkgs lvpIcd nativeInputs buildInputs;
          # Fetch raw ACVP JSON blobs (fixed revision) and filter them to SHA2-128s.
          keygenVecRaw = pkgs.fetchurl {
            url = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/d98cad66639bf9d0822129c4bcae7a169fcf9ca6/gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json";
            sha256 = "sha256-18U6G2RQCHBHtXqug6WlGgrIns2yPr4HHoP7tprp2SA=";
          };
          signingVecRaw = pkgs.fetchurl {
            url = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/d98cad66639bf9d0822129c4bcae7a169fcf9ca6/gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json";
            sha256 = "sha256-YrQufCf9pd6KlKuilDrkE7WbbqCBQfO8A1sezq4jXbo=";
          };
          verifyingVecRaw = pkgs.fetchurl {
            url = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/d98cad66639bf9d0822129c4bcae7a169fcf9ca6/gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json";
            sha256 = "sha256-oBP8IQT07UeZ2W1RFB9luWWWmyzxBkZiagIbbUVs55I=";
          };
          # Use the helper script to filter the downloaded blobs; keep outputs in a derivation.
          testVectors = pkgs.runCommand "slhvk-test-vectors" { buildInputs = [ pkgs.python3 ]; } ''
            mkdir -p $out
            cp ${./download_test_vectors.py} ./download_test_vectors.py
            python3 ./download_test_vectors.py \
              --keygen ${keygenVecRaw} \
              --signing ${signingVecRaw} \
              --verifying ${verifyingVecRaw}
            mv tests/vectors/keygen.json $out/keygen.json
            mv tests/vectors/signing.json $out/signing.json
            mv tests/vectors/verifying.json $out/verifying.json
          '';

          commonInstall = ''
            runHook preInstall
            mkdir -p $out/lib $out/include $out/bin
            cp lib/libslhvk.a $out/lib/
            cp include/slhvk.h $out/include/
            cp tests/bin/bench/*.test tests/runner $out/bin/
            for prog in $out/bin/*.test $out/bin/runner; do
              wrapProgram "$prog" \
                --set-default VK_ICD_FILENAMES ${lvpIcd}
            done
            runHook postInstall
          '';
        in {
          default = pkgs.stdenv.mkDerivation {
            pname = "slhvk";
            version = "unstable";
            src = ./.;

            nativeBuildInputs = nativeInputs ++ [ pkgs.makeWrapper ];
            buildInputs = buildInputs;

            enableParallelBuilding = true;
            doCheck = true;
            checkPhase = ''
              # Use a temporary home/cache so shader caches don't try to write into read-only Nix store.
              export HOME=$TMPDIR
              export XDG_CACHE_HOME=$TMPDIR
              # Force CPU ICD so tests run on machines without a GPU and are deterministic in CI.
              export VK_ICD_FILENAMES=${lvpIcd}
              export SLHVK_FORCE_CPU=1
              make unit
            '';

            buildPhase = ''
              mkdir -p tests/vectors
              cp ${testVectors}/* tests/vectors/
              make build-tests
            '';

            installPhase = commonInstall;
          };

          san = pkgs.stdenv.mkDerivation {
            pname = "slhvk-sanitized";
            version = "unstable";
            src = ./.;

            nativeBuildInputs = nativeInputs ++ [ pkgs.makeWrapper ];
            buildInputs = buildInputs;

            enableParallelBuilding = true;
            doCheck = true;
            checkPhase = ''
              # Use a temporary home/cache so shader caches don't try to write into read-only Nix store.
              export HOME=$TMPDIR
              export XDG_CACHE_HOME=$TMPDIR
              # Force CPU ICD so tests run on machines without a GPU and are deterministic in CI.
              export VK_ICD_FILENAMES=${lvpIcd}
              export SLHVK_FORCE_CPU=1
              make unit-san
            '';

            buildPhase = ''
              mkdir -p tests/vectors
              cp ${testVectors}/* tests/vectors/
              make build-tests-san
            '';

            installPhase = commonInstall;
          };
        });

      devShells = forAllSystems (system:
        let
          cfg = perSystem system;
          inherit (cfg) pkgs lvpIcd nativeInputs buildInputs;
        in {
          default = pkgs.mkShell {
            buildInputs = nativeInputs ++ buildInputs ++ [
              pkgs.vulkan-tools      # vulkaninfo, etc.
              pkgs.mesa              # software Vulkan ICD (lavapipe) for CPU runs
              pkgs.python3           # for download_test_vectors.py
            ];

            shellHook = ''
              # Default to CPU Vulkan ICD if user hasn't selected one.
              if [ -z "$VK_ICD_FILENAMES" ]; then
                export VK_ICD_FILENAMES=${lvpIcd}
              fi
            '';
          };
        });
    };
}
