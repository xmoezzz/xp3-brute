use eframe::egui::{self, Color32, RichText, ScrollArea, TextEdit};
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use xp3_brute::Archive;

const ACCENT: Color32 = Color32::from_rgb(73, 186, 211);
const OK: Color32 = Color32::from_rgb(93, 211, 159);
const WARN: Color32 = Color32::from_rgb(245, 185, 87);
const MUTED: Color32 = Color32::from_rgb(143, 155, 179);

enum JobEvent {
    Line(String),
    Finished(Result<(), String>),
}

fn forward_lines<R: Read + Send + 'static>(
    stream: R,
    sender: mpsc::Sender<JobEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            let _ = sender.send(JobEvent::Line(line));
        }
    })
}

fn cli_executable() -> PathBuf {
    if let Some(path) = std::env::var_os("XP3BRUTE_BIN") {
        return PathBuf::from(path);
    }
    if let Some(sibling) = std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.parent()
                .map(|parent| parent.join(format!("xp3brute{}", std::env::consts::EXE_SUFFIX)))
        })
        .filter(|path| path.is_file())
    {
        return sibling;
    }
    PathBuf::from("xp3brute")
}

struct Xp3Desktop {
    archive_path: String,
    output_dir: String,
    search: String,
    archive: Option<Archive>,
    selected: Option<usize>,
    status: String,
    logs: Vec<String>,
    job: Option<Receiver<JobEvent>>,
    unpacker_all: bool,
    verbose: bool,
}

impl Default for Xp3Desktop {
    fn default() -> Self {
        Self {
            archive_path: String::new(),
            output_dir: String::from("xp3-output"),
            search: String::new(),
            archive: None,
            selected: None,
            status: String::from("Choose an XP3 archive to begin."),
            logs: Vec::new(),
            job: None,
            unpacker_all: true,
            verbose: false,
        }
    }
}

impl Xp3Desktop {
    fn open_archive(&mut self) {
        let path = PathBuf::from(self.archive_path.trim());
        match Archive::open(&path) {
            Ok(archive) => {
                let entries = archive.entries.len();
                self.archive = Some(archive);
                self.selected = None;
                self.logs.clear();
                self.status = format!("Loaded {entries} entries from {}", path.display());
            }
            Err(error) => self.status = format!("Could not open archive: {error}"),
        }
    }

    fn export_selected_raw(&mut self) {
        let Some(archive) = self.archive.as_ref() else {
            self.status = "Open an archive first.".into();
            return;
        };
        let Some(index) = self.selected else {
            self.status = "Select an entry first.".into();
            return;
        };
        let output = PathBuf::from(self.output_dir.trim()).join(format!("entry-{index:05}.bin"));
        match archive.reconstruct_entry(index) {
            Ok(bytes) => {
                if let Some(parent) = output.parent() {
                    if let Err(error) = std::fs::create_dir_all(parent) {
                        self.status = format!("Could not create output directory: {error}");
                        return;
                    }
                }
                match std::fs::write(&output, bytes) {
                    Ok(()) => {
                        self.status =
                            format!("Wrote reconstructed raw entry to {}", output.display())
                    }
                    Err(error) => self.status = format!("Could not write entry: {error}"),
                }
            }
            Err(error) => self.status = format!("Could not reconstruct entry: {error}"),
        }
    }

    fn start_full_unpack(&mut self) {
        if self.job.is_some() {
            return;
        }
        let archive = self.archive_path.trim().to_owned();
        let output = self.output_dir.trim().to_owned();
        if archive.is_empty() || output.is_empty() {
            self.status = "Archive and output paths are required.".into();
            return;
        }

        let unpacker_all = self.unpacker_all;
        let verbose = self.verbose;
        let (sender, receiver) = mpsc::channel();
        self.logs.clear();
        self.status = "Starting full recovery pipeline…".into();
        self.job = Some(receiver);
        thread::spawn(move || {
            let mut command = Command::new(cli_executable());
            command
                .arg("unpack")
                .arg(&archive)
                .arg(&output)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if unpacker_all {
                command.arg("--unpacker-all");
            }
            if verbose {
                command.arg("--verbose");
            }

            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(error) => {
                    let _ = sender.send(JobEvent::Finished(Err(format!(
                        "Could not start xp3brute. Set XP3BRUTE_BIN to its path: {error}"
                    ))));
                    return;
                }
            };
            let mut readers = Vec::new();
            if let Some(stdout) = child.stdout.take() {
                readers.push(forward_lines(stdout, sender.clone()));
            }
            if let Some(stderr) = child.stderr.take() {
                readers.push(forward_lines(stderr, sender.clone()));
            }
            let outcome = child
                .wait()
                .map_err(|error| error.to_string())
                .and_then(|status| {
                    status
                        .success()
                        .then_some(())
                        .ok_or_else(|| format!("xp3brute exited with {status}"))
                });
            for reader in readers {
                let _ = reader.join();
            }
            let _ = sender.send(JobEvent::Finished(outcome));
        });
    }

    fn poll_job(&mut self, ctx: &egui::Context) {
        let mut done = false;
        if let Some(receiver) = &self.job {
            while let Ok(event) = receiver.try_recv() {
                match event {
                    JobEvent::Line(line) => {
                        if line.starts_with("status ") || line.starts_with("summary ") {
                            self.status = line.clone();
                        }
                        self.logs.push(line);
                    }
                    JobEvent::Finished(Ok(())) => {
                        self.status = "Full unpack completed.".into();
                        done = true;
                    }
                    JobEvent::Finished(Err(error)) => {
                        self.status = format!("Unpack failed: {error}");
                        done = true;
                    }
                }
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        if done {
            self.job = None;
        }
    }

    fn archive_summary(&self) -> Option<(usize, u64, bool)> {
        self.archive.as_ref().map(|archive| {
            (
                archive.entries.len(),
                archive.physical_size(),
                archive.is_hxv4(),
            )
        })
    }
}

impl eframe::App for Xp3Desktop {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_job(ctx);

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.heading(RichText::new("XP3 BRUTE").color(ACCENT).strong());
                ui.label(RichText::new("desktop workbench").color(MUTED));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let label = if self.job.is_some() {
                        "RECOVERING"
                    } else {
                        "READY"
                    };
                    let color = if self.job.is_some() { WARN } else { OK };
                    ui.label(RichText::new(label).color(color).strong());
                });
            });
            ui.add_space(8.0);
        });

        egui::SidePanel::left("controls")
            .min_width(310.0)
            .show(ctx, |ui| {
                ui.add_space(10.0);
                ui.heading("Workspace");
                ui.label(RichText::new("Archive").color(MUTED));
                ui.horizontal(|ui| {
                    ui.add(TextEdit::singleline(&mut self.archive_path).hint_text("data.xp3"));
                    if ui.button("Browse").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("XP3", &["xp3"])
                            .pick_file()
                        {
                            self.archive_path = path.display().to_string();
                        }
                    }
                });
                if ui.button("Open archive").clicked() {
                    self.open_archive();
                }
                ui.add_space(12.0);
                ui.label(RichText::new("Output directory").color(MUTED));
                ui.horizontal(|ui| {
                    ui.add(TextEdit::singleline(&mut self.output_dir));
                    if ui.button("Browse").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.output_dir = path.display().to_string();
                        }
                    }
                });
                ui.checkbox(&mut self.unpacker_all, "Convert supported resources");
                ui.checkbox(&mut self.verbose, "Keep recovery diagnostics");
                ui.add_space(6.0);
                let running = self.job.is_some();
                if ui
                    .add_enabled(
                        !running,
                        egui::Button::new(RichText::new("Run full unpack").strong()),
                    )
                    .clicked()
                {
                    self.start_full_unpack();
                }
                if ui.button("Export selected raw entry").clicked() {
                    self.export_selected_raw();
                }
                ui.add_space(14.0);
                ui.separator();
                ui.label(RichText::new("Current state").color(MUTED));
                ui.label(&self.status);
                if let Some((entries, bytes, hxv4)) = self.archive_summary() {
                    ui.add_space(8.0);
                    ui.label(format!("{entries} entries  ·  {} MiB", bytes / 1024 / 1024));
                    if hxv4 {
                        ui.label(RichText::new("HXV4 protected archive").color(WARN));
                    }
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.heading("Archive contents");
                ui.add_space(10.0);
                ui.add(TextEdit::singleline(&mut self.search).hint_text("Filter by name…"));
            });
            ui.separator();
            if let Some(archive) = self.archive.as_ref() {
                let needle = self.search.to_ascii_lowercase();
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (index, entry) in archive.entries.iter().enumerate() {
                            let name = entry.preferred_name();
                            if !needle.is_empty() && !name.to_ascii_lowercase().contains(&needle) {
                                continue;
                            }
                            let selected = self.selected == Some(index);
                            let kind = if entry.is_protected_dummy() {
                                "meta"
                            } else if entry.hxv4_id.is_some() {
                                "hxv4"
                            } else {
                                "file"
                            };
                            ui.horizontal(|ui| {
                                if ui
                                    .selectable_label(selected, format!("{index:05}"))
                                    .clicked()
                                {
                                    self.selected = Some(index);
                                }
                                ui.label(
                                    RichText::new(kind)
                                        .color(if kind == "file" { OK } else { WARN })
                                        .monospace(),
                                );
                                ui.label(name);
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            RichText::new(format!("{} B", entry.original_size))
                                                .color(MUTED),
                                        );
                                    },
                                );
                            });
                        }
                    });
            } else {
                ui.add_space(48.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new("Open an XP3 archive to inspect its contents.")
                            .color(MUTED)
                            .size(18.0),
                    );
                });
            }

            ui.add_space(8.0);
            ui.separator();
            ui.label(RichText::new("Operation log").color(MUTED));
            ScrollArea::vertical()
                .max_height(130.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in self.logs.iter().rev().take(200).rev() {
                        ui.monospace(line);
                    }
                });
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 720.0])
            .with_min_inner_size([860.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "XP3 Brute",
        options,
        Box::new(|creation_context| {
            creation_context.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::<Xp3Desktop>::default())
        }),
    )
}
