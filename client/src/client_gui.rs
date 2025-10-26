use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use rfd::FileDialog;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

mod client;
mod middleware;

use client::{Client, RequestStatus};
use middleware::ClientMiddleware;

#[derive(Debug)]
enum Command {
    Encrypt(PathBuf),
    Decrypt(PathBuf),
}

#[derive(Debug)]
enum UiEvent {
    Queued(u64),
    Error(String),
}

struct GuiApp {
    client: Arc<Client>,
    cmd_tx: Sender<Command>,
    evt_rx: Receiver<UiEvent>,
    selected_file: Option<PathBuf>,
}

impl GuiApp {
    fn new(client: Arc<Client>, cmd_tx: Sender<Command>, evt_rx: Receiver<UiEvent>) -> Self {
        Self {
            client,
            cmd_tx,
            evt_rx,
            selected_file: None,
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll background events
        while let Ok(evt) = self.evt_rx.try_recv() {
            match evt {
                UiEvent::Queued(id) => {
                    println!("Queued request: {}", id);
                }
                UiEvent::Error(msg) => {
                    eprintln!("UI Error: {}", msg);
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Distributed P2P Client GUI");

            ui.horizontal(|ui| {
                if ui.button("Select File...").clicked() {
                    if let Some(path) = FileDialog::new().pick_file() {
                        self.selected_file = Some(path);
                    }
                }

                if let Some(p) = &self.selected_file {
                    ui.label(p.to_string_lossy());
                } else {
                    ui.label("No file selected");
                }
            });

            ui.separator();

            ui.horizontal(|ui| {
                if ui.button("Encrypt").clicked() {
                    if let Some(p) = &self.selected_file {
                        let _ = self.cmd_tx.send(Command::Encrypt(p.clone()));
                    }
                }

                if ui.button("Decrypt").clicked() {
                    if let Some(p) = &self.selected_file {
                        let _ = self.cmd_tx.send(Command::Decrypt(p.clone()));
                    }
                }
            });

            ui.separator();

            ui.label("Requests:");
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (id, status) in self.client.tracker.list_all() {
                    ui.horizontal(|ui| match status {
                        RequestStatus::Pending => {
                            ui.label(format!("#{} | ⏳ Pending", id));
                        }
                        RequestStatus::InProgress => {
                            ui.label(format!("#{} | 🔄 In Progress", id));
                        }
                        RequestStatus::Completed(ref resp) => {
                            ui.label(format!(
                                "#{} | ✓ {}",
                                id,
                                resp.output_path.as_ref().unwrap_or(&"N/A".to_string())
                            ));
                        }
                        RequestStatus::Failed(ref err) => {
                            ui.label(format!("#{} | ✗ {}", id, err));
                        }
                    });
                }
            });
        });

        ctx.request_repaint_after(Duration::from_millis(500)); // refresh regularly
    }
}

fn spawn_worker(client: Arc<Client>, cmd_rx: Receiver<Command>, evt_tx: Sender<UiEvent>) {
    thread::spawn(move || {
        while let Ok(cmd) = cmd_rx.recv() {
            match cmd {
                Command::Encrypt(path) => {
                    match client.request_encryption(path.to_string_lossy().as_ref()) {
                        Ok(id) => {
                            let _ = evt_tx.send(UiEvent::Queued(id));
                        }
                        Err(e) => {
                            let _ = evt_tx.send(UiEvent::Error(format!("Encrypt error: {}", e)));
                        }
                    }
                }
                Command::Decrypt(path) => {
                    match client.request_decryption(path.to_string_lossy().as_ref()) {
                        Ok(id) => {
                            let _ = evt_tx.send(UiEvent::Queued(id));
                        }
                        Err(e) => {
                            let _ = evt_tx.send(UiEvent::Error(format!("Decrypt error: {}", e)));
                        }
                    }
                }
            }
        }
    });
}

fn main() {
    // --- Configuration ---
    let username = "user_gui";
    let client_ip = "127.0.0.1";
    let client_port = 8080u16;
    let middleware_ip = "127.0.0.1";
    let middleware_port = 9000u16;

    // Multiple backend servers (adjust as needed)
    let server_urls = vec![
        "http://127.0.0.1:8000".to_string(),
        "http://10.40.50.186:8000".to_string(),
    ];

    // --- Start middleware in background ---
    let middleware = ClientMiddleware::new(middleware_ip, middleware_port, server_urls);
    let middleware_handle = thread::spawn(move || {
        if let Err(e) = middleware.start() {
            eprintln!("[GUI main] Middleware error: {}", e);
        }
    });

    // Give middleware a bit of time to start listening
    thread::sleep(Duration::from_millis(200));

    let middleware_addr = format!("{}:{}", middleware_ip, middleware_port);
    let client = Arc::new(Client::new(
        username,
        client_ip,
        client_port,
        &middleware_addr,
    ));

    let (cmd_tx, cmd_rx) = unbounded::<Command>();
    let (evt_tx, evt_rx) = unbounded::<UiEvent>();
    spawn_worker(client.clone(), cmd_rx, evt_tx);

    let app = GuiApp::new(client, cmd_tx, evt_rx);

    let native_options = eframe::NativeOptions::default();
    if let Err(e) = eframe::run_native(
        "Distributed P2P Client",
        native_options,
        Box::new(move |_cc| Box::new(app)),
    ) {
        eprintln!("Failed to start GUI: {}", e);
    }

    // --- Wait for middleware thread to finish (usually never) ---
    let _ = middleware_handle.join();
}
