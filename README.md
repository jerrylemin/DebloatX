# DebloatX

DebloatX is a Windows desktop maintenance app built with a Rust core. It scans the current account's temporary folder, previews selected files before moving them into a restorable quarantine, and can show known file extensions in Explorer with a journaled, reversible current-user setting.

## Current status

- The cleanup and recovery slice and the Explorer file-extension setting are implemented; 13 Windows tests cover their core behavior.
- Explorer's `HideFileExt` setting changes only after explicit confirmation. Its original value is restored only when no conflicting value has replaced DebloatX's setting.
- Applications, Drives, and Drivers remain placeholders; most planned Windows settings are not implemented.
- The 35-source behavior survey is incomplete. See [research sources](docs/research/sources.md) and [coverage](docs/research/coverage.md).

## Build and run

Requirements: Windows 10 or 11 x64 and a current stable Rust toolchain with the MSVC target.

```powershell
cargo run
```

Run the verification commands:

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

## Cleanup and recovery behavior

The first slice scans the current user's temporary directory without modifying it. It lists ordinary files, skips reparse points and hard links, and does not follow network paths. The user selects files, reviews the count and bytes, then confirms moving the files to `%LOCALAPPDATA%\DebloatX\history`. The quarantine must be on the same local volume as the source.

Every operation writes a manifest and a flushed journal. Recovery reconciles journal state with the filesystem, restores only matching files, and leaves an existing destination untouched. Cancellation is checked between files. This slice does not delete files; users should close applications that may be using selected temporary files before moving them.

## Explorer setting

The Windows page can show known file extensions in File Explorer. It previews the exact HKCU target and saves the previous value's existence, type, and bytes before changing it to `HideFileExt=REG_DWORD 0` in the 64-bit registry view. Recovery checks the live value before restoring and reports a conflict without overwriting later changes. If several DebloatX applies are active, restore the newest one first. The setting page never creates the Explorer Advanced key. Explorer may need to be reopened for its display to refresh.

## License and research

This repository's license is MIT; see [LICENSE](LICENSE). Win11Debloat's standalone registry file and BleachBit are behavior references only. No upstream code, cleaner rules, translations, registry files, or assets are copied. Source revisions, license checks, and remaining survey work are tracked in [docs/research/sources.md](docs/research/sources.md) and [docs/research/coverage.md](docs/research/coverage.md).
