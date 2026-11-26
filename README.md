# DebloatX

DebloatX is a Windows desktop maintenance app built with a Rust core. Its first implemented slice scans the current account's temporary folder, lets the user choose individual files, previews the selection, and moves confirmed files into a per-operation quarantine with a restore history.

## Current status

- The initial cleanup and recovery slice is implemented and covered by eight Windows tests.
- No Windows settings, applications, services, drivers, or system files are changed.
- The UI has navigation for the planned sections, but Applications, Drives, Windows, and Drivers are placeholders.
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

## License and research

This repository's license is MIT; see [LICENSE](LICENSE). BleachBit is used only as a behavior reference. No upstream code, cleaner rules, translations, or assets are copied. Source revisions, license checks, and remaining survey work are tracked in [docs/research/sources.md](docs/research/sources.md).
