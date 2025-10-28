use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use image;
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
    original_image: Option<egui::TextureHandle>,
    encrypted_image: Option<egui::TextureHandle>,
    current_request_id: Option<u64>,
}

impl GuiApp {
    fn new(client: Arc<Client>, cmd_tx: Sender<Command>, evt_rx: Receiver<UiEvent>) -> Self {
        Self {
            client,
            cmd_tx,
            evt_rx,
            selected_file: None,
            original_image: None,
            encrypted_image: None,
            current_request_id: None,
        }
    }

    fn load_image(&self, path: &PathBuf, ctx: &egui::Context) -> Option<egui::TextureHandle> {
        println!("[GUI] Trying to load image from: {:?}", path);

        if !path.exists() {
            eprintln!("[GUI] File does not exist: {:?}", path);
            return None;
        }

        match image::open(path) {
            Ok(image) => {
                let size = [image.width() as usize, image.height() as usize];
                let image_buffer = image.to_rgba8();
                let pixels = image_buffer.as_flat_samples();
                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());
                let tex = ctx.load_texture(
                    path.to_string_lossy().to_string(),
                    color_image,
                    Default::default(),
                );
                println!("[GUI] Successfully loaded image {:?}", path);
                Some(tex)
            }
            Err(e) => {
                eprintln!("[GUI] Failed to load image at {:?}: {}", path, e);
                None
            }
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
                    self.current_request_id = Some(id);
                }
                UiEvent::Error(msg) => {
                    eprintln!("UI Error: {}", msg);
                }
            }
        }

        // Check if encryption is completed
        if let Some(req_id) = self.current_request_id {
            if let Some(status) = self.client.tracker.get_status(req_id) {
                if let RequestStatus::Completed(ref resp) = status {
                    if let Some(ref output_path) = resp.output_path {
                        let encrypted_path = PathBuf::from(output_path);
                        if encrypted_path.exists() {
                            println!("[GUI] Loading encrypted image from {:?}", encrypted_path);
                            self.encrypted_image = self.load_image(&encrypted_path, ctx);
                        } else {
                            eprintln!("[GUI] Encrypted file not found yet at {:?}", encrypted_path);
                        }
                        self.current_request_id = None;
                    }
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Distributed P2P Client GUI");

            // File selection
            ui.horizontal(|ui| {
                if ui.button("Select File...").clicked() {
                    if let Some(path) = FileDialog::new().pick_file() {
                        println!("[GUI] Selected file: {:?}", path);
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

            // Encrypt/Decrypt buttons
            ui.horizontal(|ui| {
                if ui.button("Encrypt").clicked() {
                    if let Some(p) = &self.selected_file {
                        self.original_image = self.load_image(p, ctx);
                        self.encrypted_image = None;
                        let _ = self.cmd_tx.send(Command::Encrypt(p.clone()));
                        println!("[GUI] Sent encrypt command for {:?}", p);
                    }
                }

                if ui.button("Decrypt").clicked() {
                    if let Some(p) = &self.selected_file {
                        let _ = self.cmd_tx.send(Command::Decrypt(p.clone()));
                        println!("[GUI] Sent decrypt command for {:?}", p);
                    }
                }
            });

            ui.separator();

            ui.label("Requests:");
            let available_height = ui.available_height();
            let requests_height = available_height * 0.3;

            egui::ScrollArea::vertical()
                .max_height(requests_height)
                .show(ui, |ui| {
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

            ui.separator();

            // Image display area
            ui.horizontal(|ui| {
                // Original Image
                ui.vertical(|ui| {
                    ui.heading("Original Image");
                    if let Some(texture) = &self.original_image {
                        ui.image(texture.id(), egui::vec2(300.0, 300.0)); // fixed size for visibility
                    } else {
                        ui.label("No image loaded");
                    }
                });

                ui.separator();

                // Encrypted Image
                ui.vertical(|ui| {
                    ui.heading("Encrypted Image");
                    if let Some(texture) = &self.encrypted_image {
                        ui.image(texture.id(), egui::vec2(300.0, 300.0));
                    } else {
                        ui.label("No encrypted image yet");
                    }
                });
            });
        });

        ctx.request_repaint_after(Duration::from_millis(500));
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

    let server_urls = vec![
        "http://127.0.0.1:8000".to_string(),
    ];

    // Start middleware in background
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

    let _ = middleware_handle.join();
}
