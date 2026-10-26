# RustDesk client (vendored)

`vendor/` is the RustDesk client source (release `1.5.0`, with the `hbb_common`
submodule flattened in as plain files) used to build a **custom client** with
your self-hosted server baked in.

- `configure_client.py` — bakes the ID server, relay server and key into
  `vendor/libs/hbb_common/src/config.rs` (compile-time constants).
- `build-client.sh` — bakes the config, then builds the `.exe` / `.apk` / Linux
  client on a machine with the RustDesk toolchain. Artifacts land in `dist/`.
  `--help` lists all options.
- `build-client.ps1` — the same for Windows PowerShell (`-Help` for options);
  builds the single-file portable `.exe` like CI.
- CI: [`.github/workflows/build-client.yml`](../.github/workflows/build-client.yml).

Full guide: [docs/custom-client.md](../docs/custom-client.md).
