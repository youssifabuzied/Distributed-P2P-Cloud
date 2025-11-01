use crossbeam_channel::{Receiver, Sender, unbounded};
use eframe::egui;
use image;
use rfd::FileDialog;
use std::collections::HashMap;
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
    Encrypt(PathBuf, u64),
    Decrypt(PathBuf),
}

#[derive(Debug)]
enum UiEvent {
    Queued(u64),
    Error(String),
}

#[derive(Debug, Clone, Copy)]
enum RequestKind {
    Encrypt,
    Decrypt,
}

struct GuiApp {
    client: Arc<Client>,
    cmd_tx: Sender<Command>,
    evt_rx: Receiver<UiEvent>,

    selected_file: Option<PathBuf>,
    original_image: Option<egui::TextureHandle>,
    encrypted_image: Option<egui::TextureHandle>,
    decrypted_image: Option<egui::TextureHandle>,

    // encrypt parameter UI
    encrypt_value: String,
    show_encrypt_box: bool,

    // mapping request id -> kind so we know how to handle completion
    request_kinds: HashMap<u64, RequestKind>,
    // temporary kind for the next queued id (set right before sending a command)
    pending_request_kind: Option<RequestKind>,

    // track the last queued id (keeps the old behavior of tracking a single "current" request)
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
            decrypted_image: None,
            encrypt_value: "10".to_string(),
            show_encrypt_box: false,
            request_kinds: HashMap::new(),
            pending_request_kind: None,
            current_request_id: None,
        }
    }

    fn load_image(&self, path: &PathBuf, ctx: &egui::Context) -> Option<egui::TextureHandle> {
        if !path.exists() {
            return None;
        }

        match image::open(path) {
            Ok(image) => {
                let size = [image.width() as usize, image.height() as usize];
                let rgba = image.to_rgba8();
                let pixels = rgba.as_flat_samples();
                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());
                Some(ctx.load_texture(
                    path.to_string_lossy().to_string(),
                    color_image,
                    Default::default(),
                ))
            }
            Err(e) => {
                eprintln!("Failed to load image {:?}: {}", path, e);
                None
            }
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process events from worker; map queued IDs to the pending kind if present
        while let Ok(evt) = self.evt_rx.try_recv() {
            match evt {
                UiEvent::Queued(id) => {
                    // assign kind for this queued id from pending (default to Encrypt if missing)
                    let kind = self
                        .pending_request_kind
                        .take()
                        .unwrap_or(RequestKind::Encrypt);
                    self.request_kinds.insert(id, kind);
                    self.current_request_id = Some(id);
                }
                UiEvent::Error(msg) => {
                    eprintln!("UI Error: {}", msg);
                }
            }
        }

        // If we have a current request id, check its status and handle completion depending on its kind
        if let Some(req_id) = self.current_request_id {
            if let Some(status) = self.client.tracker.get_status(req_id) {
                if let RequestStatus::Completed(ref resp) = status {
                    if let Some(ref output_path) = resp.output_path {
                        let out_path = PathBuf::from(output_path);
                        if out_path.exists() {
                            // determine kind for this request id
                            if let Some(kind) = self.request_kinds.get(&req_id).cloned() {
                                match kind {
                                    RequestKind::Encrypt => {
                                        // load encrypted image into the encrypted_image slot (right side)
                                        self.encrypted_image = self.load_image(&out_path, ctx);
                                    }
                                    RequestKind::Decrypt => {
                                        // load decrypted image into the decrypted_image slot (right side for decrypt flow)
                                        self.decrypted_image = self.load_image(&out_path, ctx);
                                    }
                                }
                            } else {
                                // fallback: treat as encrypt
                                self.encrypted_image = self.load_image(&out_path, ctx);
                            }
                        }
                    }
                    // cleanup mapping and current id
                    self.request_kinds.remove(&req_id);
                    self.current_request_id = None;
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Distributed P2P Client GUI");

            // File selection
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

            // Encrypt/Decrypt buttons
            ui.horizontal(|ui| {
                if ui.button("Encrypt").clicked() {
                    if let Some(p) = &self.selected_file {
                        // show mini parameter box and preload original image (left)
                        self.original_image = self.load_image(p, ctx);
                        self.encrypted_image = None;
                        self.decrypted_image = None;
                        self.show_encrypt_box = true;
                    }
                }

                if ui.button("Decrypt").clicked() {
                    if let Some(p) = &self.selected_file {
                        // show encrypted image on the left immediately
                        self.encrypted_image = self.load_image(p, ctx);
                        // ensure decrypted slot is cleared until completion
                        self.decrypted_image = None;

                        // set pending kind so when the worker replies with a Queued(id) we mark it as decrypt
                        self.pending_request_kind = Some(RequestKind::Decrypt);
                        let _ = self.cmd_tx.send(Command::Decrypt(p.clone()));
                    }
                }
            });

            // Small encrypt parameter textbox that appears after pressing Encrypt
            if self.show_encrypt_box {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Number of views:");
                    ui.text_edit_singleline(&mut self.encrypt_value);

                    if ui.button("Start").clicked() {
                        if let Some(p) = &self.selected_file {
                            match self.encrypt_value.parse::<u64>() {
                                Ok(v) => {
                                    // set pending kind so queued id is mapped to Encrypt
                                    self.pending_request_kind = Some(RequestKind::Encrypt);
                                    let _ = self.cmd_tx.send(Command::Encrypt(p.clone(), v));
                                    self.show_encrypt_box = false;
                                }
                                Err(_) => {
                                    ui.label("Invalid number");
                                }
                            }
                        }
                    }

                    if ui.button("Cancel").clicked() {
                        self.show_encrypt_box = false;
                    }
                });
            }

            ui.separator();

            // Compact request count and the request list in the same format as before
            let requests = self.client.tracker.list_all();
            ui.horizontal(|ui| {
                ui.label(format!("Requests: {}", requests.len()));
            });

            let available_height = ui.available_height();
            let requests_height = available_height * 0.3;

            egui::ScrollArea::vertical()
                .max_height(requests_height)
                .show(ui, |ui| {
                    for (id, status) in requests {
                        ui.horizontal(|ui| match status {
                            RequestStatus::Pending => {
                                ui.label(format!("#{} | Pending", id));
                            }
                            RequestStatus::InProgress => {
                                ui.label(format!("#{} | In Progress", id));
                            }
                            RequestStatus::Completed(ref resp) => {
                                ui.label(format!(
                                    "#{} | {}",
                                    id,
                                    resp.output_path.as_ref().unwrap_or(&"N/A".to_string())
                                ));
                            }
                            RequestStatus::Failed(ref err) => {
                                ui.label(format!("#{} | {}", id, err));
                            }
                        });
                    }
                });

            ui.separator();

            // Image display area:
            // For encrypt flow: left = Original Image, right = Encrypted Image
            // For decrypt flow:  left = Encrypted Image, right = Decrypted Image
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    // Determine left label: if we have a pending/last request id and it's decrypt, show "Encrypted Image"
                    let left_label = if let Some(id) = self.current_request_id {
                        if let Some(kind) = self.request_kinds.get(&id) {
                            match kind {
                                RequestKind::Decrypt => "Encrypted Image",
                                RequestKind::Encrypt => "Original Image",
                            }
                        } else {
                            "Original Image"
                        }
                    } else {
                        // if no current tracked id, use loaded slots: if decrypted_image is Some, we likely were in decrypt mode earlier
                        if self.decrypted_image.is_some() {
                            "Encrypted Image"
                        } else {
                            "Original Image"
                        }
                    };
                    ui.heading(left_label);

                    // Choose which texture to show on the left
                    let left_tex = if left_label == "Encrypted Image" {
                        &self.encrypted_image
                    } else {
                        &self.original_image
                    };

                    if let Some(tex) = left_tex {
                        ui.image(tex.id(), egui::vec2(300.0, 300.0));
                    } else {
                        ui.label("None");
                    }
                });

                ui.separator();

                ui.vertical(|ui| {
                    // Right label depends on whether it was decrypt or encrypt
                    let right_label = if let Some(id) = self.current_request_id {
                        if let Some(kind) = self.request_kinds.get(&id) {
                            match kind {
                                RequestKind::Decrypt => "Decrypted Image",
                                RequestKind::Encrypt => "Encrypted Image",
                            }
                        } else {
                            "Encrypted Image"
                        }
                    } else {
                        // If decrypted_image exists, show it; otherwise show encrypted
                        if self.decrypted_image.is_some() {
                            "Decrypted Image"
                        } else {
                            "Encrypted Image"
                        }
                    };
                    ui.heading(right_label);

                    let right_tex = if right_label == "Decrypted Image" {
                        &self.decrypted_image
                    } else {
                        &self.encrypted_image
                    };

                    if let Some(tex) = right_tex {
                        ui.image(tex.id(), egui::vec2(300.0, 300.0));
                    } else {
                        ui.label("None");
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
                Command::Encrypt(path, val) => {
                    match client.request_encryption(path.to_string_lossy().as_ref(), val) {
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
    let username = "user_gui";
    let client_ip = "127.0.0.1";
    let client_port = 8080u16;
    let middleware_ip = "127.0.0.1";
    let middleware_port = 9000u16;

    let server_urls = vec!["http://127.0.0.1:8000".to_string()];

    let middleware = ClientMiddleware::new(middleware_ip, middleware_port, server_urls);
    let middleware_handle = thread::spawn(move || {
        if let Err(e) = middleware.start() {
            eprintln!("[GUI main] Middleware error: {}", e);
        }
    });

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
