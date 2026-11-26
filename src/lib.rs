use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, Metadata, OpenOptions};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW,
    GetFileInformationByHandle,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_DWORD,
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
#[cfg(test)]
use windows_sys::Win32::System::Registry::{
    REG_BINARY, REG_CREATED_NEW_KEY, RegCreateKeyExW, RegDeleteTreeW,
};
use windows_sys::Win32::System::WindowsProgramming::{DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOTE};

pub const QUARANTINE_OPERATION_ID: &str = "cleanup.quarantine-files.v1";
pub const SHOW_FILE_EXTENSIONS_OPERATION_ID: &str = "windows.show-file-extensions.v1";
const EXPLORER_ADVANCED_KEY: &str =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced";
const HIDE_FILE_EXT_VALUE: &str = "HideFileExt";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
static NEXT_OPERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFingerprint {
    volume_serial: u32,
    file_index: u64,
    size_bytes: u64,
    last_write_time: u64,
    link_count: u32,
}

#[derive(Clone, Debug)]
pub struct ScannedFile {
    pub path: PathBuf,
    pub fingerprint: FileFingerprint,
    pub selected: bool,
}

impl ScannedFile {
    pub fn size_bytes(&self) -> u64 {
        self.fingerprint.size_bytes
    }

    pub fn display_name(&self) -> String {
        self.path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    }
}

#[derive(Clone, Debug, Default)]
pub struct ScanReport {
    pub root: PathBuf,
    pub files: Vec<ScannedFile>,
    pub visited_entries: usize,
    pub skipped_reparse_points: usize,
    pub skipped_hard_links: usize,
    pub skipped_unverifiable_files: usize,
    pub errors: Vec<String>,
    pub cancelled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    Pending,
    Quarantined,
    Restored,
    Failed,
    Changed,
    Conflict,
    Missing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Running,
    Completed,
    Partial,
    Cancelled,
    Restored,
    Interrupted,
}

#[derive(Clone, Debug)]
pub struct HistoryItem {
    pub source: PathBuf,
    pub quarantine_path: PathBuf,
    pub size_bytes: u64,
    pub status: ItemStatus,
    pub message: Option<String>,
}

#[derive(Clone, Debug)]
pub struct OperationHistory {
    pub id: String,
    pub operation_id: String,
    pub created_unix_seconds: u64,
    pub root: PathBuf,
    pub status: OperationStatus,
    pub items: Vec<HistoryItem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryValue {
    pub kind: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingStatus {
    Running,
    Applied,
    Restored,
    Failed,
    Conflict,
    Interrupted,
}

#[derive(Clone, Debug)]
pub struct SettingHistory {
    pub id: String,
    pub operation_id: String,
    pub created_unix_seconds: u64,
    pub original: Option<RegistryValue>,
    pub current: Option<RegistryValue>,
    pub status: SettingStatus,
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SettingManifest {
    id: String,
    operation_id: String,
    created_unix_seconds: u64,
    key_existed: bool,
    registry_view: u32,
    original: Option<RegistryValue>,
}

#[derive(Serialize, Deserialize)]
struct SettingJournalEvent {
    status: SettingStatus,
    message: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    id: String,
    operation_id: String,
    created_unix_seconds: u64,
    root: PathBuf,
    items: Vec<ManifestItem>,
}

#[derive(Serialize, Deserialize)]
struct ManifestItem {
    source: PathBuf,
    quarantine_path: PathBuf,
    fingerprint: FileFingerprint,
}

#[derive(Serialize, Deserialize)]
struct JournalEvent {
    item_index: Option<usize>,
    item_status: Option<ItemStatus>,
    operation_status: Option<OperationStatus>,
    message: Option<String>,
}

pub fn scan_folder<F, P>(
    root: &Path,
    storage_root: &Path,
    mut is_cancelled: F,
    mut progress: P,
) -> io::Result<ScanReport>
where
    F: FnMut() -> bool,
    P: FnMut(usize),
{
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || is_reparse_point(&root_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "thư mục quét không hợp lệ hoặc là reparse point",
        ));
    }
    ensure_local_drive(root)?;
    let root = fs::canonicalize(root)?;
    let excluded = fs::canonicalize(storage_root).unwrap_or_else(|_| storage_root.to_path_buf());
    if root.starts_with(&excluded) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "không thể quét bên trong vùng dữ liệu DebloatX",
        ));
    }

    let mut report = ScanReport {
        root: root.clone(),
        ..ScanReport::default()
    };
    let mut pending = vec![root];
    while let Some(directory) = pending.pop() {
        if is_cancelled() {
            report.cancelled = true;
            break;
        }
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) => {
                report
                    .errors
                    .push(format!("{}: {error}", directory.display()));
                continue;
            }
        };
        if !metadata.is_dir() || is_reparse_point(&metadata) {
            report.skipped_reparse_points += 1;
            continue;
        }
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                report
                    .errors
                    .push(format!("{}: {error}", directory.display()));
                continue;
            }
        };
        for entry in entries {
            if is_cancelled() {
                report.cancelled = true;
                break;
            }
            report.visited_entries += 1;
            progress(report.visited_entries);
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    report.errors.push(error.to_string());
                    continue;
                }
            };
            let path = entry.path();
            if path.starts_with(&excluded) {
                continue;
            }
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    report.errors.push(format!("{}: {error}", path.display()));
                    continue;
                }
            };
            if is_reparse_point(&metadata) {
                report.skipped_reparse_points += 1;
                continue;
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                let information = match file_information(&path) {
                    Ok(information) => information,
                    Err(_) => {
                        report.skipped_unverifiable_files += 1;
                        continue;
                    }
                };
                if information.nNumberOfLinks > 1 {
                    report.skipped_hard_links += 1;
                    continue;
                }
                match fingerprint_from_information(information) {
                    Ok(fingerprint) => report.files.push(ScannedFile {
                        path,
                        fingerprint,
                        selected: false,
                    }),
                    Err(_) => report.skipped_unverifiable_files += 1,
                }
            }
        }
        if report.cancelled {
            break;
        }
    }
    report.files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(report)
}

pub fn quarantine_files<F, P>(
    root: &Path,
    storage_root: &Path,
    files: &[ScannedFile],
    mut is_cancelled: F,
    mut progress: P,
) -> io::Result<OperationHistory>
where
    F: FnMut() -> bool,
    P: FnMut(usize, usize),
{
    if files.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "chưa chọn tệp"));
    }
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || is_reparse_point(&root_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "thư mục gốc đã thay đổi",
        ));
    }
    let root = fs::canonicalize(root)?;
    ensure_local_drive(&root)?;
    prepare_storage(storage_root)?;
    let storage_root = fs::canonicalize(storage_root)?;
    ensure_same_volume(&root, &storage_root)?;

    let mut unique_paths = HashSet::with_capacity(files.len());
    let root_volume = volume_serial(&root)?;
    for file in files {
        if !file.path.starts_with(&root)
            || file.path == root
            || !unique_paths.insert(file.path.clone())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "danh sách tệp không thuộc thư mục đã quét hoặc bị lặp",
            ));
        }
        if file.fingerprint.volume_serial != root_volume {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tệp nằm trên ổ khác với thư mục đã quét",
            ));
        }
    }

    let history_root = storage_root.join("history");
    fs::create_dir_all(&history_root)?;
    let id = new_operation_id();
    let operation_dir = history_root.join(&id);
    fs::create_dir(&operation_dir)?;
    let items_dir = operation_dir.join("items");
    fs::create_dir(&items_dir)?;
    let manifest = Manifest {
        id: id.clone(),
        operation_id: QUARANTINE_OPERATION_ID.to_owned(),
        created_unix_seconds: now_unix_seconds(),
        root: root.clone(),
        items: files
            .iter()
            .enumerate()
            .map(|(index, file)| ManifestItem {
                source: file.path.clone(),
                quarantine_path: items_dir.join(format!("{index}.item")),
                fingerprint: file.fingerprint.clone(),
            })
            .collect(),
    };
    write_manifest(&operation_dir, &manifest)?;
    append_event(
        &operation_dir,
        JournalEvent {
            item_index: None,
            item_status: None,
            operation_status: Some(OperationStatus::Running),
            message: None,
        },
    )?;

    let total = files.len();
    let mut failures = 0;
    let mut cancelled = false;
    for (index, file) in files.iter().enumerate() {
        if is_cancelled() {
            cancelled = true;
            break;
        }
        let expected_volume = file.fingerprint.volume_serial;
        let current = fs::symlink_metadata(&file.path);
        let status = match current {
            Ok(metadata) if is_reparse_point(&metadata) || !metadata.is_file() => Err((
                ItemStatus::Changed,
                "tệp đã thành reparse point hoặc không còn là tệp".to_owned(),
            )),
            Ok(_) => match file_information(&file.path) {
                Ok(information) if information.nNumberOfLinks > 1 => Err((
                    ItemStatus::Changed,
                    "tệp hiện có nhiều hard link".to_owned(),
                )),
                Ok(information) => match fingerprint_from_information(information) {
                    Ok(actual)
                        if actual == file.fingerprint
                            && actual.volume_serial == expected_volume =>
                    {
                        // shortcut: path-based rename can race a same-user path swap; replace with handle-based rename before elevated or adversarial paths are supported.
                        match fs::rename(&file.path, &manifest.items[index].quarantine_path) {
                            Ok(()) => Ok(()),
                            Err(error) => Err((ItemStatus::Failed, error.to_string())),
                        }
                    }
                    Ok(_) => Err((ItemStatus::Changed, "tệp đã đổi sau khi quét".to_owned())),
                    Err(error) => Err((ItemStatus::Changed, error.to_string())),
                },
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    Err((ItemStatus::Missing, "tệp không còn tồn tại".to_owned()))
                }
                Err(error) => Err((ItemStatus::Failed, error.to_string())),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Err((ItemStatus::Missing, "tệp không còn tồn tại".to_owned()))
            }
            Err(error) => Err((ItemStatus::Failed, error.to_string())),
        };
        match status {
            Ok(()) => {
                append_event(
                    &operation_dir,
                    JournalEvent {
                        item_index: Some(index),
                        item_status: Some(ItemStatus::Quarantined),
                        operation_status: None,
                        message: None,
                    },
                )?;
            }
            Err((item_status, message)) => {
                append_event(
                    &operation_dir,
                    JournalEvent {
                        item_index: Some(index),
                        item_status: Some(item_status),
                        operation_status: None,
                        message: Some(message),
                    },
                )?;
                failures += 1;
            }
        }
        progress(index + 1, total);
    }
    let status = if cancelled {
        OperationStatus::Cancelled
    } else if failures > 0 {
        OperationStatus::Partial
    } else {
        OperationStatus::Completed
    };
    append_event(
        &operation_dir,
        JournalEvent {
            item_index: None,
            item_status: None,
            operation_status: Some(status),
            message: None,
        },
    )?;
    history_for_dir(&operation_dir)
}

pub fn restore_operation<F, P>(
    storage_root: &Path,
    operation_id: &str,
    mut is_cancelled: F,
    mut progress: P,
) -> io::Result<OperationHistory>
where
    F: FnMut() -> bool,
    P: FnMut(usize, usize),
{
    if operation_id.is_empty()
        || !operation_id
            .chars()
            .all(|ch| ch.is_ascii_digit() || ch == '-')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ID thao tác không hợp lệ",
        ));
    }
    let operation_dir = storage_root.join("history").join(operation_id);
    let mut operation = history_for_dir(&operation_dir)?;
    let manifest = read_manifest(&operation_dir)?;
    let total = operation.items.len();
    let mut failures = 0;
    let mut cancelled = false;
    for (index, item) in operation.items.iter_mut().enumerate() {
        if item.status != ItemStatus::Quarantined {
            continue;
        }
        if is_cancelled() {
            cancelled = true;
            break;
        }
        let expected = &manifest.items[index].fingerprint;
        let target_exists = match fs::symlink_metadata(&item.source) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                append_event(
                    &operation_dir,
                    JournalEvent {
                        item_index: Some(index),
                        item_status: Some(ItemStatus::Failed),
                        operation_status: None,
                        message: Some(error.to_string()),
                    },
                )?;
                item.status = ItemStatus::Failed;
                item.message = Some(error.to_string());
                failures += 1;
                progress(index + 1, total);
                continue;
            }
        };
        let current = fs::symlink_metadata(&item.quarantine_path);
        let result = if target_exists {
            Err((
                ItemStatus::Conflict,
                "đích đã có tệp; giữ nguyên bản cách ly".to_owned(),
            ))
        } else {
            match current {
                Ok(metadata) if is_reparse_point(&metadata) || !metadata.is_file() => Err((
                    ItemStatus::Conflict,
                    "tệp trong vùng cách ly đã bị thay đổi".to_owned(),
                )),
                Ok(_) if fingerprint(&item.quarantine_path).ok().as_ref() != Some(expected) => {
                    Err((
                        ItemStatus::Conflict,
                        "nội dung hoặc danh tính tệp cách ly đã thay đổi".to_owned(),
                    ))
                }
                Ok(_) => {
                    let parent = item.source.parent().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "đường dẫn khôi phục không hợp lệ",
                        )
                    })?;
                    let parent_metadata = fs::symlink_metadata(parent);
                    if !parent_metadata
                        .as_ref()
                        .is_ok_and(|metadata| metadata.is_dir() && !is_reparse_point(metadata))
                    {
                        Err((
                            ItemStatus::Conflict,
                            "thư mục gốc không còn tồn tại".to_owned(),
                        ))
                    } else if ensure_local_drive(parent).is_err()
                        || ensure_same_volume(
                            parent,
                            item.quarantine_path
                                .parent()
                                .unwrap_or(&item.quarantine_path),
                        )
                        .is_err()
                    {
                        Err((
                            ItemStatus::Conflict,
                            "volume khôi phục không còn hợp lệ".to_owned(),
                        ))
                    } else {
                        match fs::rename(&item.quarantine_path, &item.source) {
                            Ok(()) => Ok(()),
                            Err(error) => Err((ItemStatus::Failed, error.to_string())),
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => Err((
                    ItemStatus::Missing,
                    "không tìm thấy tệp trong vùng cách ly".to_owned(),
                )),
                Err(error) => Err((ItemStatus::Failed, error.to_string())),
            }
        };
        match result {
            Ok(()) => {
                append_event(
                    &operation_dir,
                    JournalEvent {
                        item_index: Some(index),
                        item_status: Some(ItemStatus::Restored),
                        operation_status: None,
                        message: None,
                    },
                )?;
                item.status = ItemStatus::Restored;
                item.message = None;
            }
            Err((item_status, message)) => {
                append_event(
                    &operation_dir,
                    JournalEvent {
                        item_index: Some(index),
                        item_status: Some(item_status),
                        operation_status: None,
                        message: Some(message.clone()),
                    },
                )?;
                item.status = item_status;
                item.message = Some(message);
                failures += 1;
            }
        }
        progress(index + 1, total);
    }
    let status = if cancelled {
        OperationStatus::Cancelled
    } else if failures > 0 {
        OperationStatus::Partial
    } else {
        OperationStatus::Restored
    };
    append_event(
        &operation_dir,
        JournalEvent {
            item_index: None,
            item_status: None,
            operation_status: Some(status),
            message: None,
        },
    )?;
    history_for_dir(&operation_dir)
}

pub fn load_history(storage_root: &Path) -> io::Result<Vec<OperationHistory>> {
    let history_root = storage_root.join("history");
    let history_metadata = match fs::symlink_metadata(&history_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !history_metadata.is_dir() || is_reparse_point(&history_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "thư mục lịch sử là reparse point",
        ));
    }
    let mut history = Vec::new();
    for entry in fs::read_dir(history_root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() && !is_reparse_point(&metadata) {
            history.push(history_for_dir(&entry.path())?);
        }
    }
    history.sort_by_key(|operation| std::cmp::Reverse(operation.created_unix_seconds));
    Ok(history)
}

pub fn show_file_extensions_value() -> io::Result<Option<RegistryValue>> {
    read_explorer_value()
}

pub fn apply_show_file_extensions(
    storage_root: &Path,
    expected_previous: Option<RegistryValue>,
) -> io::Result<SettingHistory> {
    prepare_storage(storage_root)?;
    let current = read_explorer_value()?;
    if current != expected_previous {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "thiết lập đã thay đổi sau khi xem trước; hãy kiểm tra lại",
        ));
    }
    let applied = shown_extensions_value();
    if current.as_ref() == Some(&applied) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "phần mở rộng đã được hiển thị",
        ));
    }

    let history_root = storage_root.join("settings-history");
    if !history_root.exists() {
        fs::create_dir(&history_root)?;
    }
    let root_metadata = fs::symlink_metadata(&history_root)?;
    if !root_metadata.is_dir() || is_reparse_point(&root_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "thư mục lịch sử thiết lập không hợp lệ",
        ));
    }

    let id = new_operation_id();
    let operation_dir = history_root.join(&id);
    fs::create_dir(&operation_dir)?;
    let manifest = SettingManifest {
        id,
        operation_id: SHOW_FILE_EXTENSIONS_OPERATION_ID.to_owned(),
        created_unix_seconds: now_unix_seconds(),
        key_existed: true,
        registry_view: KEY_WOW64_64KEY,
        original: current,
    };
    write_setting_manifest(&operation_dir, &manifest)?;
    append_setting_event(
        &operation_dir,
        SettingJournalEvent {
            status: SettingStatus::Running,
            message: None,
        },
    )?;

    let result = write_explorer_value(Some(&applied));
    let observed = read_explorer_value();
    let (status, message) = match observed {
        Ok(Some(value)) if value == applied => (SettingStatus::Applied, None),
        Ok(value) if value == manifest.original => (
            SettingStatus::Failed,
            result.err().map(|error| error.to_string()).or_else(|| {
                Some("Windows không lưu giá trị dự kiến; giá trị ban đầu vẫn còn.".to_owned())
            }),
        ),
        Ok(_) => (
            SettingStatus::Conflict,
            Some("giá trị đã đổi trong lúc áp dụng; không ghi đè giá trị mới".to_owned()),
        ),
        Err(error) => (
            SettingStatus::Interrupted,
            Some(format!(
                "không đọc lại được registry sau khi áp dụng: {error}"
            )),
        ),
    };
    append_setting_event(&operation_dir, SettingJournalEvent { status, message })?;
    setting_history_for_dir(&operation_dir)
}

pub fn load_setting_history(storage_root: &Path) -> io::Result<Vec<SettingHistory>> {
    let history_root = storage_root.join("settings-history");
    let metadata = match fs::symlink_metadata(&history_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "thư mục lịch sử thiết lập không hợp lệ",
        ));
    }
    let mut history = Vec::new();
    for entry in fs::read_dir(history_root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() && !is_reparse_point(&metadata) {
            history.push(setting_history_for_dir(&entry.path())?);
        }
    }
    history.sort_by_key(|operation| std::cmp::Reverse(operation.created_unix_seconds));
    Ok(history)
}

pub fn restore_setting(storage_root: &Path, operation_id: &str) -> io::Result<SettingHistory> {
    if operation_id.is_empty()
        || !operation_id
            .chars()
            .all(|ch| ch.is_ascii_digit() || ch == '-')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ID thao tác không hợp lệ",
        ));
    }
    let operation_dir = storage_root.join("settings-history").join(operation_id);
    let manifest = read_setting_manifest(&operation_dir)?;
    let history = load_setting_history(storage_root)?;
    if latest_applied_setting_id(&history).is_some_and(|latest| latest != operation_id) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "có lần áp dụng mới hơn đang hoạt động; hãy khôi phục mục mới nhất trước",
        ));
    }
    let current = read_explorer_value()?;
    match registry_restore_decision(
        current.as_ref(),
        manifest.original.as_ref(),
        &shown_extensions_value(),
    ) {
        RegistryRestoreDecision::AlreadyRestored => {
            append_setting_event(
                &operation_dir,
                SettingJournalEvent {
                    status: SettingStatus::Restored,
                    message: None,
                },
            )?;
        }
        RegistryRestoreDecision::Restore => {
            append_setting_event(
                &operation_dir,
                SettingJournalEvent {
                    status: SettingStatus::Running,
                    message: None,
                },
            )?;
            // shortcut: registry writes have no compare-and-swap; after-write verification catches only races that remain visible.
            let result = write_explorer_value(manifest.original.as_ref());
            let observed = read_explorer_value();
            let (status, message) = match observed {
                Ok(value) if value == manifest.original => (SettingStatus::Restored, None),
                Ok(Some(value)) if value == shown_extensions_value() => {
                    let (status, message) = match result {
                        Err(error) => (SettingStatus::Failed, error.to_string()),
                        Ok(()) => (
                            SettingStatus::Interrupted,
                            "Windows báo ghi thành công nhưng giá trị gốc chưa xuất hiện; có thể thử lại sau khi đối chiếu.".to_owned(),
                        ),
                    };
                    (status, Some(message))
                }
                Ok(_) => (
                    SettingStatus::Conflict,
                    Some("giá trị đã đổi trong lúc khôi phục; không ghi đè giá trị mới".to_owned()),
                ),
                Err(error) => (
                    SettingStatus::Interrupted,
                    Some(result.err().map_or_else(
                        || format!("không đọc lại được registry sau khi khôi phục: {error}"),
                        |e| e.to_string(),
                    )),
                ),
            };
            append_setting_event(&operation_dir, SettingJournalEvent { status, message })?;
        }
        RegistryRestoreDecision::Conflict => {
            append_setting_event(
                &operation_dir,
                SettingJournalEvent {
                    status: SettingStatus::Conflict,
                    message: Some(
                        "giá trị hiện tại khác cả giá trị đã áp dụng và giá trị gốc; cần kiểm tra thủ công"
                            .to_owned(),
                    ),
                },
            )?;
        }
    }
    setting_history_for_dir(&operation_dir)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegistryRestoreDecision {
    AlreadyRestored,
    Restore,
    Conflict,
}

fn registry_restore_decision(
    current: Option<&RegistryValue>,
    original: Option<&RegistryValue>,
    applied: &RegistryValue,
) -> RegistryRestoreDecision {
    if current == original {
        RegistryRestoreDecision::AlreadyRestored
    } else if current == Some(applied) {
        RegistryRestoreDecision::Restore
    } else {
        RegistryRestoreDecision::Conflict
    }
}

fn setting_operation_order(id: &str) -> Option<(u128, u32, u64)> {
    let mut parts = id.split('-');
    let order = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    (parts.next().is_none() && order.0 != 0).then_some(order)
}

fn latest_applied_setting_id(history: &[SettingHistory]) -> Option<&str> {
    history
        .iter()
        .filter(|operation| operation.status == SettingStatus::Applied)
        .max_by_key(|operation| setting_operation_order(&operation.id))
        .map(|operation| operation.id.as_str())
}

fn shown_extensions_value() -> RegistryValue {
    RegistryValue {
        kind: REG_DWORD,
        data: 0_u32.to_le_bytes().to_vec(),
    }
}

fn read_explorer_value() -> io::Result<Option<RegistryValue>> {
    read_registry_value(EXPLORER_ADVANCED_KEY, HIDE_FILE_EXT_VALUE)
}

fn read_registry_value(key_path: &str, value_name: &str) -> io::Result<Option<RegistryValue>> {
    with_registry_key(key_path, KEY_QUERY_VALUE, |key| {
        let name = value_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        for _ in 0..3 {
            let mut kind = 0;
            let mut length = 0;
            // SAFETY: key is open, name is nul-terminated, and output pointers are valid.
            let status = unsafe {
                RegQueryValueExW(
                    key,
                    name.as_ptr(),
                    null(),
                    &mut kind,
                    null_mut(),
                    &mut length,
                )
            };
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            if length > 1_048_576 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "giá trị registry vượt quá 1 MiB",
                ));
            }
            let mut data = vec![0; length as usize];
            let mut actual_length = length;
            // SAFETY: data has length bytes and its pointer remains valid for the call.
            let status = unsafe {
                RegQueryValueExW(
                    key,
                    name.as_ptr(),
                    null(),
                    &mut kind,
                    if data.is_empty() {
                        null_mut()
                    } else {
                        data.as_mut_ptr()
                    },
                    &mut actual_length,
                )
            };
            if status == ERROR_MORE_DATA {
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            data.truncate(actual_length as usize);
            return Ok(Some(RegistryValue { kind, data }));
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "giá trị registry liên tục thay đổi khi đọc",
        ))
    })
}

fn write_explorer_value(value: Option<&RegistryValue>) -> io::Result<()> {
    write_registry_value(EXPLORER_ADVANCED_KEY, HIDE_FILE_EXT_VALUE, value)
}

fn write_registry_value(
    key_path: &str,
    value_name: &str,
    value: Option<&RegistryValue>,
) -> io::Result<()> {
    with_registry_key(key_path, KEY_SET_VALUE, |key| {
        let name = value_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let status = match value {
            Some(value) => {
                let length = u32::try_from(value.data.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "giá trị registry quá lớn")
                })?;
                // SAFETY: key and name are valid; data points to length bytes for the call.
                unsafe {
                    RegSetValueExW(
                        key,
                        name.as_ptr(),
                        0,
                        value.kind,
                        if value.data.is_empty() {
                            null()
                        } else {
                            value.data.as_ptr()
                        },
                        length,
                    )
                }
            }
            None => {
                // SAFETY: key is open and name is a nul-terminated value name.
                unsafe { RegDeleteValueW(key, name.as_ptr()) }
            }
        };
        if status == ERROR_SUCCESS || (value.is_none() && status == ERROR_FILE_NOT_FOUND) {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    })
}

fn with_registry_key<T>(
    key_path: &str,
    access: u32,
    action: impl FnOnce(HKEY) -> io::Result<T>,
) -> io::Result<T> {
    let path = key_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut key = null_mut();
    // SAFETY: path is nul-terminated and key points to writable storage.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            path.as_ptr(),
            0,
            access | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let result = action(key);
    // SAFETY: key is the valid handle returned by RegOpenKeyExW above.
    unsafe { RegCloseKey(key) };
    result
}

fn write_setting_manifest(operation_dir: &Path, manifest: &SettingManifest) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(operation_dir.join("operation.json"))?;
    serde_json::to_writer(&mut file, manifest).map_err(io::Error::other)?;
    file.sync_all()
}

fn append_setting_event(operation_dir: &Path, event: SettingJournalEvent) -> io::Result<()> {
    let path = operation_dir.join("events.jsonl");
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (!metadata.is_file() || is_reparse_point(&metadata))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal thiết lập không hợp lệ",
        ));
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, &event).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn read_setting_manifest(operation_dir: &Path) -> io::Result<SettingManifest> {
    let metadata = fs::symlink_metadata(operation_dir)?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "thư mục thao tác thiết lập không hợp lệ",
        ));
    }
    let path = operation_dir.join("operation.json");
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "manifest thiết lập không hợp lệ",
        ));
    }
    let manifest: SettingManifest =
        serde_json::from_slice(&fs::read(path)?).map_err(io::Error::other)?;
    if manifest.id
        != operation_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .as_ref()
        || manifest.operation_id != SHOW_FILE_EXTENSIONS_OPERATION_ID
        || !manifest.key_existed
        || manifest.registry_view != KEY_WOW64_64KEY
        || setting_operation_order(&manifest.id).is_none()
        || manifest.original.as_ref() == Some(&shown_extensions_value())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "phạm vi manifest thiết lập không hợp lệ",
        ));
    }
    Ok(manifest)
}

fn setting_history_for_dir(operation_dir: &Path) -> io::Result<SettingHistory> {
    let manifest = read_setting_manifest(operation_dir)?;
    let events_path = operation_dir.join("events.jsonl");
    let mut event_status = None;
    let mut event_message = None;
    if let Ok(metadata) = fs::symlink_metadata(&events_path)
        && (!metadata.is_file() || is_reparse_point(&metadata))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal thiết lập không hợp lệ",
        ));
    }
    if let Ok(bytes) = fs::read(events_path) {
        let valid_length = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        for line in bytes[..valid_length].split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let event: SettingJournalEvent =
                serde_json::from_slice(line).map_err(io::Error::other)?;
            event_status = Some(event.status);
            event_message = event.message;
        }
    }
    let current = read_explorer_value();
    let (status, message) = match &current {
        Ok(current) => reconcile_setting_state(
            event_status,
            event_message,
            current.as_ref(),
            manifest.original.as_ref(),
            &shown_extensions_value(),
        ),
        Err(error) => (SettingStatus::Failed, Some(error.to_string())),
    };
    Ok(SettingHistory {
        id: manifest.id,
        operation_id: manifest.operation_id,
        created_unix_seconds: manifest.created_unix_seconds,
        original: manifest.original,
        current: current.ok().flatten(),
        status,
        message,
    })
}

fn reconcile_setting_state(
    event_status: Option<SettingStatus>,
    event_message: Option<String>,
    current: Option<&RegistryValue>,
    original: Option<&RegistryValue>,
    applied: &RegistryValue,
) -> (SettingStatus, Option<String>) {
    match event_status {
        Some(SettingStatus::Restored) => (
            SettingStatus::Restored,
            (current != original)
                .then(|| "đã khôi phục trước đây; giá trị đã đổi sau thao tác này".to_owned()),
        ),
        Some(SettingStatus::Failed) => (SettingStatus::Failed, event_message),
        Some(SettingStatus::Conflict) => (SettingStatus::Conflict, event_message),
        _ if current == Some(applied) => (SettingStatus::Applied, None),
        _ if current == original => (
            if event_status == Some(SettingStatus::Applied) {
                SettingStatus::Restored
            } else {
                SettingStatus::Interrupted
            },
            (event_status != Some(SettingStatus::Applied)).then(|| {
                "giá trị hiện tại bằng giá trị gốc; chưa xác nhận thao tác đã áp dụng".to_owned()
            }),
        ),
        _ => (
            SettingStatus::Conflict,
            Some("giá trị hiện tại khác cả giá trị đã áp dụng và giá trị gốc".to_owned()),
        ),
    }
}

pub fn local_storage_root() -> io::Result<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "LOCALAPPDATA chưa được thiết lập")
        })?;
    Ok(local_app_data.join("DebloatX"))
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut amount = bytes as f64;
    let mut unit = 0;
    while amount >= 1024.0 && unit < UNITS.len() - 1 {
        amount /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{amount:.1} {}", UNITS[unit])
    }
}

fn prepare_storage(storage_root: &Path) -> io::Result<()> {
    let parent = storage_root.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "đường dẫn lưu trữ không hợp lệ",
        )
    })?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir() || is_reparse_point(&parent_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "LOCALAPPDATA không phải thư mục cục bộ hợp lệ",
        ));
    }
    ensure_local_drive(parent)?;
    if !storage_root.exists() {
        fs::create_dir(storage_root)?;
    }
    let storage_metadata = fs::symlink_metadata(storage_root)?;
    if !storage_metadata.is_dir() || is_reparse_point(&storage_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "thư mục lưu trữ DebloatX không hợp lệ",
        ));
    }
    Ok(())
}

fn ensure_same_volume(source: &Path, destination: &Path) -> io::Result<()> {
    if volume_serial(source)? != volume_serial(destination)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "thư mục tạm và vùng cách ly nằm trên ổ khác nhau",
        ));
    }
    Ok(())
}

fn ensure_local_drive(path: &Path) -> io::Result<()> {
    let prefix = path.components().next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "đường dẫn không có volume gốc")
    })?;
    if matches!(prefix, Component::Prefix(prefix) if matches!(prefix.kind(), std::path::Prefix::UNC(_, _) | std::path::Prefix::VerbatimUNC(_, _)))
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "không hỗ trợ thư mục trên network share",
        ));
    }
    let mut root = OsString::from(prefix.as_os_str());
    root.push("\\");
    let wide = root
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: `wide` is a null-terminated UTF-16 path that remains alive for the call.
    let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
    if drive_type == DRIVE_REMOTE {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "không hỗ trợ thư mục trên network share",
        ));
    }
    if drive_type != DRIVE_FIXED && drive_type != DRIVE_RAMDISK {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "chỉ hỗ trợ ổ cục bộ cố định",
        ));
    }
    Ok(())
}

fn volume_serial(path: &Path) -> io::Result<u32> {
    Ok(file_information(path)?.dwVolumeSerialNumber)
}

fn file_information(path: &Path) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is owned by `file`, and `information` is writable for the call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tệp là reparse point",
        ));
    }
    Ok(information)
}

fn fingerprint(path: &Path) -> io::Result<FileFingerprint> {
    fingerprint_from_information(file_information(path)?)
}

fn fingerprint_from_information(
    information: BY_HANDLE_FILE_INFORMATION,
) -> io::Result<FileFingerprint> {
    Ok(FileFingerprint {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        size_bytes: (u64::from(information.nFileSizeHigh) << 32)
            | u64::from(information.nFileSizeLow),
        last_write_time: (u64::from(information.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(information.ftLastWriteTime.dwLowDateTime),
        link_count: information.nNumberOfLinks,
    })
}

fn is_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn new_operation_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = NEXT_OPERATION.fetch_add(1, Ordering::Relaxed);
    format!("{nanos}-{}-{counter}", std::process::id())
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn write_manifest(operation_dir: &Path, manifest: &Manifest) -> io::Result<()> {
    let path = operation_dir.join("operation.json");
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer(&mut file, manifest).map_err(io::Error::other)?;
    file.sync_all()
}

fn append_event(operation_dir: &Path, event: JournalEvent) -> io::Result<()> {
    let path = operation_dir.join("events.jsonl");
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (is_reparse_point(&metadata) || !metadata.is_file())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tệp journal không hợp lệ",
        ));
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, &event).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn read_manifest(operation_dir: &Path) -> io::Result<Manifest> {
    let path = operation_dir.join("operation.json");
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "manifest thao tác không hợp lệ",
        ));
    }
    let manifest: Manifest = serde_json::from_slice(&fs::read(path)?).map_err(io::Error::other)?;
    if manifest.id
        != operation_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .as_ref()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ID manifest không khớp thư mục journal",
        ));
    }
    if manifest.operation_id != QUARANTINE_OPERATION_ID
        || !manifest.root.is_absolute()
        || manifest
            .root
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "phạm vi manifest thao tác không hợp lệ",
        ));
    }
    let canonical_operation_dir = fs::canonicalize(operation_dir)?;
    let mut sources = HashSet::with_capacity(manifest.items.len());
    for (index, item) in manifest.items.iter().enumerate() {
        if !item.source.is_absolute()
            || item.source == manifest.root
            || !item.source.starts_with(&manifest.root)
            || item
                .source
                .components()
                .any(|component| component == Component::ParentDir)
            || item.quarantine_path
                != canonical_operation_dir
                    .join("items")
                    .join(format!("{index}.item"))
            || !sources.insert(item.source.clone())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "đường dẫn mục trong manifest thao tác không hợp lệ",
            ));
        }
    }
    Ok(manifest)
}

fn history_for_dir(operation_dir: &Path) -> io::Result<OperationHistory> {
    let metadata = fs::symlink_metadata(operation_dir)?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "thư mục thao tác không hợp lệ",
        ));
    }
    let manifest = read_manifest(operation_dir)?;
    let mut states = vec![(ItemStatus::Pending, None); manifest.items.len()];
    let mut operation_status = None;
    let events_path = operation_dir.join("events.jsonl");
    if let Ok(event_metadata) = fs::symlink_metadata(&events_path)
        && (!event_metadata.is_file() || is_reparse_point(&event_metadata))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal sự kiện không hợp lệ",
        ));
    }
    if let Ok(bytes) = fs::read(events_path) {
        let valid_length = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        for line in bytes[..valid_length].split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let event: JournalEvent = serde_json::from_slice(line).map_err(io::Error::other)?;
            if let Some(index) = event.item_index {
                let state = states.get_mut(index).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "journal trỏ tới mục không tồn tại",
                    )
                })?;
                if let Some(status) = event.item_status {
                    *state = (status, event.message);
                }
            }
            if let Some(status) = event.operation_status {
                operation_status = Some(status);
            }
        }
    }

    let mut items = Vec::with_capacity(manifest.items.len());
    for (index, item) in manifest.items.iter().enumerate() {
        let (mut status, mut message) = states[index].clone();
        reconcile_item(item, &mut status, &mut message);
        items.push(HistoryItem {
            source: item.source.clone(),
            quarantine_path: item.quarantine_path.clone(),
            size_bytes: item.fingerprint.size_bytes,
            status,
            message,
        });
    }
    let status = match operation_status {
        Some(OperationStatus::Running) | None => OperationStatus::Interrupted,
        Some(status) => status,
    };
    Ok(OperationHistory {
        id: manifest.id,
        operation_id: manifest.operation_id,
        created_unix_seconds: manifest.created_unix_seconds,
        root: manifest.root,
        status,
        items,
    })
}

fn reconcile_item(item: &ManifestItem, status: &mut ItemStatus, message: &mut Option<String>) {
    let source = match fs::symlink_metadata(&item.source) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            *status = ItemStatus::Conflict;
            *message = Some(format!("không kiểm tra được đường dẫn gốc: {error}"));
            return;
        }
    };
    let quarantine = match fs::symlink_metadata(&item.quarantine_path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            *status = ItemStatus::Conflict;
            *message = Some(format!("không kiểm tra được vùng cách ly: {error}"));
            return;
        }
    };
    let source_matches =
        source.is_some() && fingerprint(&item.source).ok().as_ref() == Some(&item.fingerprint);
    let quarantine_matches = quarantine.is_some()
        && fingerprint(&item.quarantine_path).ok().as_ref() == Some(&item.fingerprint);
    match (
        source.is_some(),
        quarantine.is_some(),
        source_matches,
        quarantine_matches,
    ) {
        (true, false, true, _)
            if matches!(*status, ItemStatus::Quarantined | ItemStatus::Restored) =>
        {
            *status = ItemStatus::Restored;
        }
        (true, false, true, _) => {}
        (false, true, _, true) => *status = ItemStatus::Quarantined,
        (true, true, _, _) => {
            *status = ItemStatus::Conflict;
            *message = Some("cả đường dẫn gốc và vùng cách ly đều có tệp".to_owned());
        }
        (true, false, false, _) => {
            *status = ItemStatus::Changed;
            *message = Some("tệp tại đường dẫn gốc đã thay đổi".to_owned());
        }
        (false, true, _, false) => {
            *status = ItemStatus::Conflict;
            *message = Some("tệp trong vùng cách ly đã thay đổi".to_owned());
        }
        (false, false, _, _) => {
            *status = ItemStatus::Missing;
            *message = Some("không tìm thấy tệp ở đường dẫn gốc hoặc vùng cách ly".to_owned());
        }
    }
}

#[cfg(test)]
fn temp_workspace() -> PathBuf {
    std::env::temp_dir().join(format!(
        "debloatx-test-{}-{}",
        std::process::id(),
        new_operation_id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRegistryKey(String);

    impl Drop for TestRegistryKey {
        fn drop(&mut self) {
            let path = self
                .0
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            // SAFETY: this test-owned unique key path is nul-terminated and isolated under HKCU\\Software.
            unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, path.as_ptr()) };
        }
    }

    fn make_file(path: &Path, contents: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn scanned_file(path: &Path) -> ScannedFile {
        ScannedFile {
            path: fs::canonicalize(path).unwrap(),
            fingerprint: fingerprint(path).unwrap(),
            selected: true,
        }
    }

    #[test]
    fn scan_finds_nested_files_and_skips_hard_links() {
        let workspace = temp_workspace();
        let root = workspace.join("temp");
        let storage = workspace.join("appdata").join("DebloatX");
        let regular = root.join("nested").join("plain.txt");
        let hard_link = root.join("nested").join("plain-copy.txt");
        make_file(&regular, b"fixture");
        fs::hard_link(&regular, &hard_link).unwrap();

        let report = scan_folder(&root, &storage, || false, |_| {}).unwrap();
        assert!(report.files.is_empty());
        assert_eq!(report.skipped_hard_links, 2);

        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn scan_skips_reparse_directories_without_following_them() {
        let workspace = temp_workspace();
        let root = workspace.join("temp");
        let outside = workspace.join("outside");
        let storage = workspace.join("appdata").join("DebloatX");
        fs::create_dir_all(&root).unwrap();
        make_file(&outside.join("keep.txt"), b"keep");
        let link = root.join("junction");
        let output = std::process::Command::new("cmd.exe")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let report = scan_folder(&root, &storage, || false, |_| {}).unwrap();
        assert!(report.files.is_empty());
        assert_eq!(report.skipped_reparse_points, 1);

        fs::remove_dir(&link).unwrap();
        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn quarantine_cancels_between_items_and_restores_without_overwrite() {
        let workspace = temp_workspace();
        let root = workspace.join("temp");
        let storage = workspace.join("appdata").join("DebloatX");
        fs::create_dir_all(storage.parent().unwrap()).unwrap();
        let first = root.join("first.tmp");
        let second = root.join("second.tmp");
        make_file(&first, b"first");
        make_file(&second, b"second");
        let files = vec![scanned_file(&first), scanned_file(&second)];
        let mut checks = 0;
        let operation = quarantine_files(
            &root,
            &storage,
            &files,
            || {
                checks += 1;
                checks == 2
            },
            |_, _| {},
        )
        .unwrap();
        assert_eq!(operation.status, OperationStatus::Cancelled);
        assert_eq!(
            operation
                .items
                .iter()
                .filter(|item| item.status == ItemStatus::Quarantined)
                .count(),
            1
        );
        assert!(first.exists() ^ second.exists());

        let history = load_history(&storage).unwrap();
        assert_eq!(history.len(), 1);
        let moved = history[0]
            .items
            .iter()
            .find(|item| item.status == ItemStatus::Quarantined)
            .unwrap();
        make_file(&moved.source, b"new file");
        let restored = restore_operation(&storage, &operation.id, || false, |_, _| {}).unwrap();
        assert_eq!(
            restored
                .items
                .iter()
                .filter(|item| item.status == ItemStatus::Conflict)
                .count(),
            1
        );
        assert!(moved.quarantine_path.exists());
        assert_eq!(fs::read(&moved.source).unwrap(), b"new file");

        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn incomplete_journal_recovers_a_move_from_the_filesystem() {
        let workspace = temp_workspace();
        let root = workspace.join("temp");
        let storage = workspace.join("appdata").join("DebloatX");
        fs::create_dir_all(storage.parent().unwrap()).unwrap();
        let source = root.join("recovered.tmp");
        make_file(&source, b"recovery");
        let file = scanned_file(&source);
        let operation = quarantine_files(&root, &storage, &[file], || false, |_, _| {}).unwrap();
        let operation_dir = storage.join("history").join(&operation.id);
        let journal = operation_dir.join("events.jsonl");
        let bytes = fs::read(&journal).unwrap();
        let last_line = bytes.iter().rposition(|byte| *byte == b'\n').unwrap();
        let first_line = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        fs::write(&journal, &bytes[..first_line]).unwrap();
        let recovered = history_for_dir(&operation_dir).unwrap();
        assert_eq!(recovered.items[0].status, ItemStatus::Quarantined);
        assert_eq!(recovered.status, OperationStatus::Interrupted);
        assert!(recovered.items[0].quarantine_path.exists());
        assert!(!recovered.items[0].source.exists());
        assert!(last_line > first_line);

        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn changed_file_after_preview_is_not_moved() {
        let workspace = temp_workspace();
        let root = workspace.join("temp");
        let storage = workspace.join("appdata").join("DebloatX");
        fs::create_dir_all(storage.parent().unwrap()).unwrap();
        let source = root.join("stale.tmp");
        make_file(&source, b"before");
        let file = scanned_file(&source);
        fs::write(&source, b"changed size").unwrap();

        let operation = quarantine_files(&root, &storage, &[file], || false, |_, _| {}).unwrap();
        assert_eq!(operation.items[0].status, ItemStatus::Changed);
        assert_eq!(fs::read(&source).unwrap(), b"changed size");

        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn tampered_manifest_cannot_redirect_restore_path() {
        let workspace = temp_workspace();
        let root = workspace.join("temp");
        let storage = workspace.join("appdata").join("DebloatX");
        fs::create_dir_all(storage.parent().unwrap()).unwrap();
        let source = root.join("quarantined.tmp");
        let protected = workspace.join("outside").join("keep.txt");
        make_file(&source, b"quarantine me");
        make_file(&protected, b"keep me");
        let operation = quarantine_files(
            &root,
            &storage,
            &[scanned_file(&source)],
            || false,
            |_, _| {},
        )
        .unwrap();
        let operation_dir = storage.join("history").join(&operation.id);
        let manifest_path = operation_dir.join("operation.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["items"][0]["quarantine_path"] =
            serde_json::Value::String(protected.display().to_string());
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        assert!(restore_operation(&storage, &operation.id, || false, |_, _| {}).is_err());
        assert!(protected.exists());
        assert!(operation.items[0].quarantine_path.exists());
        assert!(!source.exists());

        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn unc_paths_are_rejected_before_file_operations() {
        assert!(ensure_local_drive(Path::new(r"\\server\share\temp")).is_err());
    }

    #[test]
    fn format_bytes_uses_binary_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
    }

    #[test]
    fn registry_restore_refuses_values_changed_after_apply() {
        let original = RegistryValue {
            kind: 3,
            data: vec![0x01, 0x02],
        };
        let applied = shown_extensions_value();
        let changed = RegistryValue {
            kind: REG_DWORD,
            data: 1_u32.to_le_bytes().to_vec(),
        };

        assert_eq!(
            registry_restore_decision(Some(&applied), Some(&original), &applied),
            RegistryRestoreDecision::Restore
        );
        assert_eq!(
            registry_restore_decision(Some(&original), Some(&original), &applied),
            RegistryRestoreDecision::AlreadyRestored
        );
        assert_eq!(
            registry_restore_decision(None, None, &applied),
            RegistryRestoreDecision::AlreadyRestored
        );
        assert_eq!(
            registry_restore_decision(Some(&changed), Some(&original), &applied),
            RegistryRestoreDecision::Conflict
        );
        assert_eq!(
            registry_restore_decision(
                Some(&RegistryValue {
                    kind: 3,
                    data: vec![1, 3]
                }),
                Some(&original),
                &applied
            ),
            RegistryRestoreDecision::Conflict
        );
    }

    #[test]
    fn setting_restore_only_targets_the_newest_active_apply() {
        let history = [
            SettingHistory {
                id: "100-1-0".to_owned(),
                operation_id: SHOW_FILE_EXTENSIONS_OPERATION_ID.to_owned(),
                created_unix_seconds: 1,
                original: None,
                current: None,
                status: SettingStatus::Applied,
                message: None,
            },
            SettingHistory {
                id: "100-1-10".to_owned(),
                operation_id: SHOW_FILE_EXTENSIONS_OPERATION_ID.to_owned(),
                created_unix_seconds: 1,
                original: None,
                current: None,
                status: SettingStatus::Applied,
                message: None,
            },
            SettingHistory {
                id: "101-1-0".to_owned(),
                operation_id: SHOW_FILE_EXTENSIONS_OPERATION_ID.to_owned(),
                created_unix_seconds: 1,
                original: None,
                current: None,
                status: SettingStatus::Restored,
                message: None,
            },
        ];

        assert_eq!(latest_applied_setting_id(&history), Some("100-1-10"));
        assert!(setting_operation_order("malformed").is_none());
        assert!(setting_operation_order("100-1-10-extra").is_none());
    }

    #[test]
    fn restored_setting_history_stays_terminal_after_a_later_apply() {
        let original = RegistryValue {
            kind: REG_DWORD,
            data: 1_u32.to_le_bytes().to_vec(),
        };
        let applied = shown_extensions_value();

        let (status, message) = reconcile_setting_state(
            Some(SettingStatus::Restored),
            None,
            Some(&applied),
            Some(&original),
            &applied,
        );
        assert_eq!(status, SettingStatus::Restored);
        assert!(message.is_some());

        let (status, _) = reconcile_setting_state(
            Some(SettingStatus::Failed),
            Some("failed".to_owned()),
            Some(&applied),
            Some(&original),
            &applied,
        );
        assert_eq!(status, SettingStatus::Failed);
    }

    #[test]
    fn interrupted_setting_that_still_matches_target_remains_recoverable() {
        let original = RegistryValue {
            kind: REG_DWORD,
            data: 1_u32.to_le_bytes().to_vec(),
        };
        let applied = shown_extensions_value();
        let (status, _) = reconcile_setting_state(
            Some(SettingStatus::Interrupted),
            Some("verification was interrupted".to_owned()),
            Some(&applied),
            Some(&original),
            &applied,
        );
        assert_eq!(status, SettingStatus::Applied);
    }

    #[test]
    fn registry_helpers_round_trip_raw_data_in_an_isolated_hkcu_key() {
        let key_path = format!(
            "Software\\DebloatX.RegistryTest.{}.{}",
            std::process::id(),
            new_operation_id()
        );
        let wide_path = key_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut key = null_mut();
        let mut disposition = 0;
        // SAFETY: the path is nul-terminated and the output pointers are valid for the call.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                wide_path.as_ptr(),
                0,
                null(),
                0,
                KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY,
                null(),
                &mut key,
                &mut disposition,
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
        // SAFETY: key is the handle returned by RegCreateKeyExW.
        unsafe { RegCloseKey(key) };
        assert_eq!(disposition, REG_CREATED_NEW_KEY);
        let _cleanup = TestRegistryKey(key_path.clone());

        let original = RegistryValue {
            kind: REG_BINARY,
            data: vec![0x00, 0x7f, 0xff],
        };
        assert_eq!(read_registry_value(&key_path, "TestValue").unwrap(), None);
        write_registry_value(&key_path, "TestValue", Some(&original)).unwrap();
        assert_eq!(
            read_registry_value(&key_path, "TestValue").unwrap(),
            Some(original)
        );
        write_registry_value(&key_path, "TestValue", None).unwrap();
        assert_eq!(read_registry_value(&key_path, "TestValue").unwrap(), None);
    }
}
