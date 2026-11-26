# Behavior coverage

Coverage is intentionally partial. Sources #1 (Win11Debloat) and #20 (BleachBit) have pinned revisions; source #1 has only been surveyed for the Explorer setting below. `verified` means the upstream behavior was traced to source at that revision; `implemented` means DebloatX code and tests cover the behavior on this checkout. The remaining sources and behavior families are not yet surveyed or classified as product exclusions.

## Implemented first slice

| ID | Source/evidence | Preconditions and scope | Before → after | Options and risk | Undo and verification | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `CLEANUP.PREVIEW.001` | #20 [`README.md`](https://github.com/bleachbit/bleachbit/blob/5dad07382af9d1ad0f713ae5734c24f4d8b82efc/README.md), [`CLI.py`](https://github.com/bleachbit/bleachbit/blob/5dad07382af9d1ad0f713ae5734c24f4d8b82efc/bleachbit/CLI.py#L90-L103), [`GuiBasic.py`](https://github.com/bleachbit/bleachbit/blob/5dad07382af9d1ad0f713ae5734c24f4d8b82efc/bleachbit/GuiBasic.py#L118-L177) | Current Windows account; read-only scan of its temp directory | No filesystem changes → list/count/size for eligible files | User selects individual files; temp data can belong to a running application | `scan_finds_nested_files_and_skips_hard_links`, `scan_skips_reparse_directories_without_following_them` | verified + implemented |
| `CLEANUP.QUARANTINE.001` | Independent implementation informed by #20's preview-before-clean flow; app code [`src/lib.rs`](../../src/lib.rs) | Ordinary files under current account temp; local fixed/RAM disk; quarantine in same volume | File stays at original path → same file is renamed into a per-operation quarantine | Explicit preview and confirmation; skip hard links/reparse points; locked or changed files fail/skip; crash can interrupt the batch | `quarantine_cancels_between_items_and_restores_without_overwrite`, `changed_file_after_preview_is_not_moved` | implemented |
| `CLEANUP.JOURNAL.001` | Independent recovery design; [`src/lib.rs`](../../src/lib.rs) | Quarantine operation creates manifest and flushed JSONL events | Journal records in-progress and per-file state → history reconciles actual paths on reopen | Corrupt manifest/journal is reported; a torn trailing event is ignored | `incomplete_journal_recovers_a_move_from_the_filesystem` | implemented |
| `CLEANUP.MANIFEST.001` | Independent path-safety design; [`src/lib.rs`](../../src/lib.rs) | Manifest action ID, root, source paths, and per-item quarantine paths are checked before use | Valid manifest → history/restore uses only paths within the recorded root and operation directory | Invalid or tampered paths reject the operation | `tampered_manifest_cannot_redirect_restore_path` | implemented |
| `CLEANUP.RESTORE.001` | Independent recovery design; [`src/lib.rs`](../../src/lib.rs) | File in quarantine matches volume/file ID/size/write time; original parent exists; same volume | Quarantined file → original path only when the destination is empty | Existing destination or mismatched file is kept and reported as a conflict | `quarantine_cancels_between_items_and_restores_without_overwrite` | implemented |
| `CLEANUP.CANCEL.001` | Independent operation design; [`src/lib.rs`](../../src/lib.rs) | Cancellation checked between selected files | Current item finishes → later items remain pending | Per-file progress; partial batches are journaled | `quarantine_cancels_between_items_and_restores_without_overwrite` | implemented |

## Implemented second slice

| ID | Source/evidence | Preconditions and scope | Before → after | Options and risk | Undo and verification | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `WINDOWS.EXPLORER.EXTENSIONS.001` | #1 standalone [registry file](https://github.com/Raphire/Win11Debloat/blob/5d88bfe9ef2be5a8a643166a6400eb78a30c46ec/Regfiles/Show_Extensions_For_Known_File_Types.reg) sets `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\HideFileExt` to `REG_DWORD 0`; independent implementation in [`src/lib.rs`](../../src/lib.rs) and [`src/main.rs`](../../src/main.rs) | Explorer Advanced key must already exist; current account and explicit 64-bit registry view; no admin rights | Captures value existence, type, and bytes → writes `REG_DWORD 0` after preview and confirmation | Rechecks preview state before apply; shows the target and scope; Explorer may need reopening; no key is created if absent | Journal and manifest preserve the original optional raw value plus key/view; restore only when the live value matches the applied DWORD or is already original; older active records cannot undo a newer apply; isolated registry and restore-history tests pass | upstream behavior verified; code implemented; 13 core tests passed; live Explorer apply not performed |

## Known limits of this slice

- No permanent deletion exists in this slice; there is no permanent-delete path to verify.
- Recycle Bin integration, cloud placeholders, long-path behavior, locked-file recovery, and power-loss fault injection were not tested.
- Rename is path-based after a fresh file-handle fingerprint check. A same-user process could race a path replacement between that check and the rename. This cleanup path is not elevated; use handle-based rename before supporting elevated or adversarial paths.
- The UI compiled but has not yet been exercised through an interactive screen-reader, DPI, or end-to-end check.
- Registry API tests use a temporary, unique HKCU test key. They verify raw value read/write/delete and restore decision logic; the real `HideFileExt` setting was not changed during verification.
- Registry has no compare-and-swap operation in this implementation. A same-user process can race a value change around apply/restore; the app rechecks before writing and verifies afterward, but this is not atomic.

## Remaining source survey

Source #1 is only partially surveyed as recorded above; sources #2–19 and #21–35 remain pending revision/license/runtime-path verification. Source #13 also needs an availability/provenance recheck. Until those surveys are done, no other behavior from those projects is claimed as verified, merged, excluded, or fully covered. Current planned families needing per-behavior decisions include AppX/MSIX and Win32 uninstall, other Windows settings/services/tasks, rule-driven cleaners, disk/duplicate analysis, MSI cache, Driver Store, Windows features, and app install/update flows.
