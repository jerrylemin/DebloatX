#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;

use debloatx::{
    HistoryItem, ItemStatus, OperationHistory, OperationStatus, ScanReport, format_bytes,
    load_history, local_storage_root, quarantine_files, restore_operation, scan_folder,
};
use eframe::egui::{self, Color32, RichText, Stroke, Theme, Vec2};

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1240.0, 820.0])
            .with_min_inner_size([980.0, 680.0]),
        ..Default::default()
    };
    eframe::run_native(
        "DebloatX",
        options,
        Box::new(|context| Ok(Box::new(DebloatApp::new(context)))),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Applications,
    Cleanup,
    Drives,
    Windows,
    Drivers,
    Recovery,
}

enum WorkerMessage {
    ScanProgress(usize),
    ScanFinished(io::Result<ScanReport>),
    ApplyProgress(usize, usize),
    ApplyFinished(io::Result<OperationHistory>),
    RestoreProgress(usize, usize),
    RestoreFinished(io::Result<OperationHistory>),
}

struct Worker {
    receiver: Receiver<WorkerMessage>,
    cancel: Arc<AtomicBool>,
}

struct DebloatApp {
    page: Page,
    storage_root: Option<std::path::PathBuf>,
    storage_error: Option<String>,
    scan: Option<ScanReport>,
    history: Vec<OperationHistory>,
    worker: Option<Worker>,
    confirm_quarantine: bool,
    progress: (usize, usize),
    progress_label: String,
    notice: Option<String>,
}

impl DebloatApp {
    fn new(context: &eframe::CreationContext<'_>) -> Self {
        configure_style(&context.egui_ctx);
        let storage_root = match local_storage_root() {
            Ok(path) => Some(path),
            Err(error) => {
                return Self {
                    page: Page::Overview,
                    storage_root: None,
                    storage_error: Some(error.to_string()),
                    scan: None,
                    history: Vec::new(),
                    worker: None,
                    confirm_quarantine: false,
                    progress: (0, 0),
                    progress_label: String::new(),
                    notice: None,
                };
            }
        };
        let (history, history_error) = match load_history(storage_root.as_ref().unwrap()) {
            Ok(history) => (history, None),
            Err(error) => (Vec::new(), Some(format!("Không đọc được lịch sử: {error}"))),
        };
        Self {
            page: Page::Overview,
            storage_root,
            storage_error: None,
            scan: None,
            history,
            worker: None,
            confirm_quarantine: false,
            progress: (0, 0),
            progress_label: String::new(),
            notice: history_error,
        }
    }

    fn start_scan(&mut self) {
        let Some(storage_root) = self.storage_root.clone() else {
            self.notice = self.storage_error.clone();
            return;
        };
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        thread::spawn(move || {
            let root = std::env::temp_dir();
            let progress_sender = sender.clone();
            let result = scan_folder(
                &root,
                &storage_root,
                || worker_cancel.load(Ordering::Relaxed),
                |visited| {
                    let _ = progress_sender.send(WorkerMessage::ScanProgress(visited));
                },
            );
            let _ = sender.send(WorkerMessage::ScanFinished(result));
        });
        self.worker = Some(Worker { receiver, cancel });
        self.progress = (0, 0);
        self.progress_label = "Đang quét thư mục tạm của tài khoản".to_owned();
        self.notice = None;
        self.confirm_quarantine = false;
    }

    fn start_quarantine(&mut self) {
        let (Some(storage_root), Some(scan)) = (self.storage_root.clone(), self.scan.as_ref())
        else {
            self.notice = self.storage_error.clone();
            return;
        };
        let selected: Vec<_> = scan
            .files
            .iter()
            .filter(|file| file.selected)
            .cloned()
            .collect();
        if selected.is_empty() {
            self.notice = Some("Chọn ít nhất một tệp trước khi tiếp tục.".to_owned());
            return;
        }
        let root = scan.root.clone();
        let total = selected.len();
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        thread::spawn(move || {
            let progress_sender = sender.clone();
            let result = quarantine_files(
                &root,
                &storage_root,
                &selected,
                || worker_cancel.load(Ordering::Relaxed),
                |done, total| {
                    let _ = progress_sender.send(WorkerMessage::ApplyProgress(done, total));
                },
            );
            let _ = sender.send(WorkerMessage::ApplyFinished(result));
        });
        self.worker = Some(Worker { receiver, cancel });
        self.progress = (0, total);
        self.progress_label = "Đang chuyển tệp vào vùng cách ly".to_owned();
        self.notice = None;
        self.confirm_quarantine = false;
    }

    fn start_restore(&mut self, operation_id: String) {
        let Some(storage_root) = self.storage_root.clone() else {
            self.notice = self.storage_error.clone();
            return;
        };
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        thread::spawn(move || {
            let progress_sender = sender.clone();
            let result = restore_operation(
                &storage_root,
                &operation_id,
                || worker_cancel.load(Ordering::Relaxed),
                |done, total| {
                    let _ = progress_sender.send(WorkerMessage::RestoreProgress(done, total));
                },
            );
            let _ = sender.send(WorkerMessage::RestoreFinished(result));
        });
        self.worker = Some(Worker { receiver, cancel });
        self.progress = (0, 0);
        self.progress_label = "Đang khôi phục tệp".to_owned();
        self.notice = None;
    }

    fn poll_worker(&mut self) {
        let messages: Vec<_> = self
            .worker
            .as_ref()
            .map(|worker| worker.receiver.try_iter().collect())
            .unwrap_or_default();
        for message in messages {
            match message {
                WorkerMessage::ScanProgress(visited) => self.progress.0 = visited,
                WorkerMessage::ScanFinished(Ok(report)) => {
                    let cancelled = report.cancelled;
                    self.progress = (report.visited_entries, report.visited_entries);
                    self.scan = Some(report);
                    self.notice = cancelled
                        .then(|| "Đã hủy quét; kết quả đang hiển thị là một phần.".to_owned());
                    self.worker = None;
                }
                WorkerMessage::ScanFinished(Err(error)) => {
                    self.notice = Some(format!("Không thể quét: {error}"));
                    self.worker = None;
                }
                WorkerMessage::ApplyProgress(done, total) => self.progress = (done, total),
                WorkerMessage::ApplyFinished(Ok(operation)) => {
                    self.notice = Some(operation_message(&operation));
                    self.history = self.reload_history();
                    self.worker = None;
                    self.page = Page::Recovery;
                }
                WorkerMessage::ApplyFinished(Err(error)) => {
                    self.notice = Some(format!(
                        "Không hoàn tất thao tác: {error}. Lịch sử đã được đối chiếu khi mở lại Khôi phục."
                    ));
                    self.history = self.reload_history();
                    self.worker = None;
                    self.page = Page::Recovery;
                }
                WorkerMessage::RestoreProgress(done, total) => self.progress = (done, total),
                WorkerMessage::RestoreFinished(Ok(operation)) => {
                    self.notice = Some(operation_message(&operation));
                    self.history = self.reload_history();
                    self.worker = None;
                }
                WorkerMessage::RestoreFinished(Err(error)) => {
                    self.notice = Some(format!("Không hoàn tất khôi phục: {error}"));
                    self.history = self.reload_history();
                    self.worker = None;
                }
            }
        }
    }

    fn reload_history(&self) -> Vec<OperationHistory> {
        self.storage_root
            .as_ref()
            .and_then(|root| load_history(root).ok())
            .unwrap_or_default()
    }

    fn cancel_worker(&mut self) {
        if let Some(worker) = &self.worker {
            worker.cancel.store(true, Ordering::Relaxed);
            self.progress_label = "Đang hủy sau mục hiện tại".to_owned();
        }
    }

    fn selected_count(&self) -> usize {
        self.scan
            .as_ref()
            .map(|scan| scan.files.iter().filter(|file| file.selected).count())
            .unwrap_or_default()
    }

    fn selected_bytes(&self) -> u64 {
        self.scan
            .as_ref()
            .map(|scan| {
                scan.files
                    .iter()
                    .filter(|file| file.selected)
                    .fold(0_u64, |total, file| total.saturating_add(file.size_bytes()))
            })
            .unwrap_or_default()
    }

    fn navigation(&mut self, ui: &mut egui::Ui) {
        ui.add_space(14.0);
        ui.heading(RichText::new("DebloatX").size(22.0).strong());
        ui.label(
            RichText::new("Bảo trì Windows có thể hoàn tác")
                .size(11.5)
                .color(Color32::from_rgb(154, 166, 182)),
        );
        ui.add_space(24.0);
        for (page, label) in [
            (Page::Overview, "Tổng quan"),
            (Page::Applications, "Ứng dụng"),
            (Page::Cleanup, "Dọn dẹp"),
            (Page::Drives, "Ổ đĩa"),
            (Page::Windows, "Windows"),
            (Page::Drivers, "Driver"),
            (Page::Recovery, "Khôi phục"),
        ] {
            let selected = self.page == page;
            let response = ui.add_sized(
                [ui.available_width(), 38.0],
                egui::Button::new(RichText::new(label).size(14.0).color(if selected {
                    Color32::WHITE
                } else {
                    Color32::from_rgb(190, 200, 213)
                }))
                .fill(if selected {
                    Color32::from_rgb(38, 91, 123)
                } else {
                    Color32::TRANSPARENT
                })
                .stroke(Stroke::NONE),
            );
            if response.clicked() {
                self.page = page;
                if page == Page::Recovery {
                    self.history = self.reload_history();
                }
            }
            ui.add_space(3.0);
        }
        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.label(
                RichText::new("Bản đầu · thao tác người dùng hiện tại")
                    .size(11.0)
                    .color(Color32::from_rgb(136, 151, 171)),
            );
        });
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Tổng quan").size(26.0));
        ui.add_space(6.0);
        ui.label("Bắt đầu bằng một lượt quét chỉ đọc. Mọi tệp được chọn sẽ được chuyển vào vùng cách ly trước khi khôi phục hoặc xóa.");
        ui.add_space(22.0);
        egui::Frame::group(ui.style())
            .fill(Color32::from_rgb(26, 36, 47))
            .corner_radius(egui::CornerRadius::same(16))
            .inner_margin(egui::Margin::same(22))
            .show(ui, |ui| {
                ui.label(RichText::new("Lát cắt hiện có").strong().color(Color32::from_rgb(106, 198, 224)));
                ui.add_space(8.0);
                ui.heading("Tệp tạm của tài khoản");
                ui.label("Quét cây thư mục tạm hiện tại, chọn từng tệp, xem trước dung lượng và khôi phục theo từng thao tác.");
                ui.add_space(14.0);
                if ui.add_sized([210.0, 42.0], egui::Button::new("Quét tệp tạm")).clicked() {
                    self.page = Page::Cleanup;
                    self.start_scan();
                }
            });
        ui.add_space(16.0);
        if !self.history.is_empty() {
            ui.label(format!(
                "{} thao tác trong lịch sử khôi phục",
                self.history.len()
            ));
        }
        if let Some(error) = &self.storage_error {
            ui.add_space(10.0);
            ui.colored_label(Color32::from_rgb(255, 176, 98), format!("Lưu ý: {error}"));
        }
    }

    fn cleanup(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.heading(RichText::new("Dọn dẹp tệp tạm").size(25.0));
                ui.label("Phạm vi: thư mục tạm của tài khoản Windows hiện tại");
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let enabled = self.worker.is_none();
                if ui
                    .add_enabled(enabled, egui::Button::new("Quét lại"))
                    .clicked()
                {
                    self.start_scan();
                }
            });
        });
        ui.add_space(16.0);
        if let Some(report) = &self.scan {
            ui.label(
                RichText::new(report.root.display().to_string())
                    .monospace()
                    .size(12.0)
                    .color(Color32::from_rgb(153, 172, 192)),
            );
        } else if self.worker.is_none() {
            ui.label("Chưa quét. Quét chỉ đọc sẽ liệt kê các tệp thông thường; thư mục, hard link và reparse point không được chọn.");
            ui.add_space(8.0);
            if ui
                .add_sized([210.0, 42.0], egui::Button::new("Quét thư mục tạm"))
                .clicked()
            {
                self.start_scan();
            }
        }
        if let Some(notice) = &self.notice {
            ui.add_space(8.0);
            ui.colored_label(Color32::from_rgb(136, 213, 181), notice);
        }
        if self.worker.is_some() {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(&self.progress_label);
                if self.progress.1 > 0 {
                    ui.label(format!("{} / {}", self.progress.0, self.progress.1));
                } else {
                    ui.label(format!("{} mục đã kiểm tra", self.progress.0));
                }
                if ui.button("Hủy").clicked() {
                    self.cancel_worker();
                }
            });
        }
        if self.confirm_quarantine {
            self.confirmation(ui);
        } else if self.scan.is_some() {
            self.scan_results(ui);
        }
    }

    fn scan_results(&mut self, ui: &mut egui::Ui) {
        let worker_idle = self.worker.is_none();
        let mut start_preview = false;
        if let Some(report) = self.scan.as_mut() {
            ui.add_space(14.0);
            let selected_count = report.files.iter().filter(|file| file.selected).count();
            let selected_bytes = report
                .files
                .iter()
                .filter(|file| file.selected)
                .fold(0_u64, |total, file| total.saturating_add(file.size_bytes()));
            ui.horizontal(|ui| {
                metric_card(ui, "Tệp có thể xem", report.files.len().to_string());
                metric_card(ui, "Đã kiểm tra", report.visited_entries.to_string());
                metric_card(
                    ui,
                    "Đã chọn",
                    format!("{selected_count} · {}", format_bytes(selected_bytes)),
                );
            });
            if report.skipped_reparse_points > 0
                || report.skipped_hard_links > 0
                || report.skipped_unverifiable_files > 0
            {
                ui.add_space(8.0);
                ui.label(format!(
                    "Bỏ qua: {} reparse point · {} hard link · {} mục không xác minh được",
                    report.skipped_reparse_points,
                    report.skipped_hard_links,
                    report.skipped_unverifiable_files
                ));
            }
            for error in report.errors.iter().take(3) {
                ui.colored_label(Color32::from_rgb(255, 176, 98), error);
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Chọn tất cả").clicked() {
                    for file in &mut report.files {
                        file.selected = true;
                    }
                }
                if ui.button("Bỏ chọn").clicked() {
                    for file in &mut report.files {
                        file.selected = false;
                    }
                }
            });
            ui.add_space(6.0);
            egui::Frame::group(ui.style())
                .fill(Color32::from_rgb(24, 33, 43))
                .corner_radius(egui::CornerRadius::same(12))
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    if report.files.is_empty() {
                        ui.label("Không tìm thấy tệp đủ điều kiện.");
                    } else {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show_rows(ui, 48.0, report.files.len(), |ui, rows| {
                                for index in rows {
                                    let file = &mut report.files[index];
                                    let label = format!(
                                        "{}  ·  {}",
                                        file.display_name(),
                                        format_bytes(file.size_bytes())
                                    );
                                    ui.checkbox(&mut file.selected, label);
                                    ui.label(
                                        RichText::new(file.path.display().to_string())
                                            .monospace()
                                            .size(10.5)
                                            .color(Color32::from_rgb(139, 156, 175)),
                                    );
                                    ui.add_space(3.0);
                                }
                            });
                    }
                });
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label("Tệp sẽ được chuyển đi; không có tệp nào bị xóa trong lát cắt này.");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let selected_count = report.files.iter().filter(|file| file.selected).count();
                    if ui
                        .add_enabled(
                            worker_idle && selected_count > 0,
                            egui::Button::new("Xem trước thao tác"),
                        )
                        .clicked()
                    {
                        start_preview = true;
                    }
                });
            });
        }
        if start_preview {
            self.confirm_quarantine = true;
            self.notice = None;
        }
    }

    fn confirmation(&mut self, ui: &mut egui::Ui) {
        ui.add_space(16.0);
        egui::Frame::group(ui.style())
            .fill(Color32::from_rgb(35, 41, 48))
            .stroke(Stroke::new(1.0, Color32::from_rgb(220, 162, 84)))
            .corner_radius(egui::CornerRadius::same(14))
            .inner_margin(egui::Margin::same(18))
            .show(ui, |ui| {
                ui.label(RichText::new("XEM TRƯỚC · XÁC NHẬN").size(12.0).strong().color(Color32::from_rgb(242, 189, 112)));
                ui.add_space(7.0);
                ui.heading("Chuyển tệp đã chọn vào vùng cách ly?");
                ui.label(format!("{} tệp · {}", self.selected_count(), format_bytes(self.selected_bytes())));
                ui.add_space(8.0);
                ui.label("DebloatX sẽ ghi journal trước khi di chuyển. Khôi phục chỉ ghi lại nếu đường dẫn gốc còn trống và danh tính tệp trong vùng cách ly khớp.");
                ui.label("Thao tác chỉ chạy trên ổ cục bộ cùng volume. Tệp đã đổi, bị khóa hoặc có đích trùng sẽ được giữ nguyên.");
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("Quay lại").clicked() {
                        self.confirm_quarantine = false;
                    }
                    if ui
                        .add_enabled(self.worker.is_none(), egui::Button::new("Xác nhận đưa vào vùng cách ly"))
                        .clicked()
                    {
                        self.start_quarantine();
                    }
                });
            });
    }

    fn recovery(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Khôi phục").size(25.0));
        ui.label("Khôi phục theo từng thao tác. Tệp gốc đã có sẽ không bị ghi đè.");
        ui.add_space(14.0);
        if self.history.is_empty() {
            ui.label("Chưa có thao tác nào trong lịch sử.");
            return;
        }
        let can_restore = self.worker.is_none();
        let mut restore_id = None;
        for operation in &self.history {
            let quarantined = operation
                .items
                .iter()
                .filter(|item| item.status == ItemStatus::Quarantined)
                .count();
            let restored = operation
                .items
                .iter()
                .filter(|item| item.status == ItemStatus::Restored)
                .count();
            let total_bytes = operation
                .items
                .iter()
                .filter(|item| item.status == ItemStatus::Quarantined)
                .fold(0_u64, |sum, item| sum.saturating_add(item.size_bytes));
            egui::Frame::group(ui.style())
                .fill(Color32::from_rgb(24, 33, 43))
                .corner_radius(egui::CornerRadius::same(12))
                .inner_margin(egui::Margin::same(14))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new(status_label(operation.status)).strong());
                            ui.label(format!(
                                "{} tệp trong vùng cách ly · {} đã khôi phục",
                                quarantined, restored
                            ));
                            ui.label(
                                RichText::new(format!(
                                    "{} · {}",
                                    operation.id,
                                    format_bytes(total_bytes)
                                ))
                                .monospace()
                                .size(11.0),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .add_enabled(
                                    can_restore && quarantined > 0,
                                    egui::Button::new("Khôi phục thao tác"),
                                )
                                .clicked()
                            {
                                restore_id = Some(operation.id.clone());
                            }
                        });
                    });
                    for item in operation.items.iter().filter(|item| {
                        matches!(
                            item.status,
                            ItemStatus::Conflict
                                | ItemStatus::Changed
                                | ItemStatus::Missing
                                | ItemStatus::Failed
                        )
                    }) {
                        show_item_issue(ui, item);
                    }
                });
            ui.add_space(8.0);
        }
        if let Some(operation_id) = restore_id {
            self.start_restore(operation_id);
        }
    }

    fn placeholder(&mut self, ui: &mut egui::Ui, title: &str) {
        ui.heading(RichText::new(title).size(25.0));
        ui.add_space(8.0);
        ui.label("Nhóm này sẽ được bổ sung theo các lát cắt tiếp theo. Chưa có thay đổi hệ thống nào được áp dụng ở đây.");
    }
}

impl eframe::App for DebloatApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_worker();
        egui::Panel::left("navigation")
            .default_size(226.0)
            .size_range(226.0..=226.0)
            .resizable(false)
            .frame(egui::Frame::side_top_panel(ui.style()).fill(Color32::from_rgb(17, 24, 33)))
            .show(ui, |ui| self.navigation(ui));
        egui::CentralPanel::default()
            .frame(
                egui::Frame::central_panel(ui.style())
                    .fill(Color32::from_rgb(22, 30, 40))
                    .inner_margin(egui::Margin::same(26)),
            )
            .show(ui, |ui| match self.page {
                Page::Overview => self.overview(ui),
                Page::Cleanup => self.cleanup(ui),
                Page::Recovery => self.recovery(ui),
                Page::Applications => self.placeholder(ui, "Ứng dụng"),
                Page::Drives => self.placeholder(ui, "Ổ đĩa"),
                Page::Windows => self.placeholder(ui, "Windows"),
                Page::Drivers => self.placeholder(ui, "Driver"),
            });
        if self.worker.is_some() {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

fn configure_style(context: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = Color32::from_rgb(22, 30, 40);
    visuals.window_fill = Color32::from_rgb(28, 37, 48);
    visuals.extreme_bg_color = Color32::from_rgb(16, 22, 30);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(38, 50, 63);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(52, 68, 84);
    visuals.widgets.active.bg_fill = Color32::from_rgb(33, 110, 136);
    visuals.selection.bg_fill = Color32::from_rgb(38, 91, 123);
    visuals.selection.stroke = Stroke::new(1.0, Color32::from_rgb(108, 202, 228));
    context.set_visuals(visuals);
    let mut style = (*context.style_of(Theme::Dark)).clone();
    style.spacing.item_spacing = Vec2::new(10.0, 9.0);
    style.spacing.button_padding = Vec2::new(12.0, 8.0);
    context.set_style_of(Theme::Dark, style);
}

fn metric_card(ui: &mut egui::Ui, title: &str, value: String) {
    egui::Frame::group(ui.style())
        .fill(Color32::from_rgb(27, 38, 50))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_min_width(150.0);
            ui.label(
                RichText::new(title)
                    .size(11.5)
                    .color(Color32::from_rgb(154, 172, 190)),
            );
            ui.label(RichText::new(value).size(18.0).strong());
        });
}

fn status_label(status: OperationStatus) -> &'static str {
    match status {
        OperationStatus::Running => "Đang xử lý",
        OperationStatus::Completed => "Đã cách ly",
        OperationStatus::Partial => "Hoàn tất một phần",
        OperationStatus::Cancelled => "Đã hủy",
        OperationStatus::Restored => "Đã khôi phục",
        OperationStatus::Interrupted => "Đã gián đoạn · cần đối chiếu",
    }
}

fn operation_message(operation: &OperationHistory) -> String {
    let quarantined = operation
        .items
        .iter()
        .filter(|item| item.status == ItemStatus::Quarantined)
        .count();
    let restored = operation
        .items
        .iter()
        .filter(|item| item.status == ItemStatus::Restored)
        .count();
    format!(
        "{} · {quarantined} tệp đang cách ly · {restored} tệp đã khôi phục",
        status_label(operation.status)
    )
}

fn show_item_issue(ui: &mut egui::Ui, item: &HistoryItem) {
    ui.horizontal_wrapped(|ui| {
        ui.colored_label(
            Color32::from_rgb(255, 176, 98),
            item.source.display().to_string(),
        );
        if let Some(message) = &item.message {
            ui.label(message);
        }
    });
}
