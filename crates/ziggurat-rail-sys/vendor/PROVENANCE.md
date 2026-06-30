# Vendored inputs

Most of what this crate compiles comes from the **Simplicity SDK 2026.6.0 conan
package**, which `build.rs` downloads and caches (see `SDK_URL`/`SDK_REV` there): the C
glue sources, all SDK headers, and the precompiled RAIL library. That is *not* vendored.

Vendored here are only the small, project-specific SLC outputs that are not part of the
SDK package:

- `config/` — SLC-generated component config headers (`sl_rail_util_*_config.h`,
  `sl_device_init_*`, clock-manager/core config, …).
- `autogen/` — SLC-generated glue: `linkerfile.ld`, the component catalog, device-init
  instances, the RAIL util init instance, etc.

These were generated from the **minimal RAIL SLC project** vendored under `../project/`
(`rail_minimal.slcp` + `app.{c,h}` + `zbt2_rail_minimal.yaml`) — a bare-bones project
that is just the RAIL library plus its init/PA/PHY/callback glue. That project's generated
build also defines the authoritative minimal source/include/define set captured in
`../recipe/`.

## Regenerating config/autogen (after an SDK bump or project change)

The project is built with NabuCasa's `silabs-firmware-builder` (Docker):

1. Copy `project/rail_minimal.slcp` + `project/app.{c,h}` to `silabs-firmware-builder/src/rail_minimal/`.
2. Copy `project/zbt2_rail_minimal.yaml` to `silabs-firmware-builder/manifests/nabucasa/zbt2/`.
3. From the builder repo:
   ```sh
   docker run --rm -v "$(pwd):/repo" silabs-firmware-builder:sdk-bump-arm64 \
     --manifest manifests/nabucasa/zbt2/zbt2_rail_minimal.yaml \
     --output gbl --output-dir artifacts --no-clean-build-dir
   ```
   (The `.gbl` postbuild fails — no `app_properties` component — which is fine; the
   generated project tree under `build/<ts>_zbt2_rail_minimal/` is what we want.)
4. Copy that tree's `config/` and `autogen/` back here, and re-derive `../recipe/*` from
   its `cmake_gcc/rail_minimal.cmake`.

## SDK fetch

`build.rs` fetches the conan package to `~/.cache/ziggurat-rail-sdk/<rev>/` (override with
`ZIGGURAT_SDK_CACHE`) and extracts it; the extraction dir is the SDK root. Set
`ZIGGURAT_SDK_TREE` to a pre-extracted SDK (or a `~/.silabs` install) to skip the download
during local development.
