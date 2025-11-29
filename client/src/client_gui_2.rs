// client_gui_2.rs - Main GUI application using egui
// Standalone GUI equivalent to client.rs functionality

mod client;
mod middleware;

use middleware::ClientMiddleware;

use eframe::egui;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// =======================================
// Data Structures
// =======================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageInfo {
    pub name: String,
    pub size: usize,
    pub path: String,
    pub shared_count: usize, // Number of users who have access
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessRight {
    pub viewer: String,
    pub accepted_views: u64,
    pub views_used: u64,
}

// =======================================
// Application State
// =======================================

#[derive(Clone, PartialEq)]
enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

#[derive(Clone, PartialEq)]
enum ActiveTab {
    MyImages,
    Discover,
    Requests,
}

#[derive(Clone)]
struct AppState {
    // Connection info
    username: String,
    client_ip: String,
    client_port: u16,
    middleware_addr: String,

    // Status
    connection_status: ConnectionStatus,
    heartbeat_active: bool,

    // Add these fields to AppState
    add_image_path: String,
    add_image_error: Option<String>,

    // UI state
    registration_error: Option<String>,
    status_message: String,
    active_tab: ActiveTab,

    // My Images tab state
    my_images: Vec<ImageInfo>,
    selected_image: Option<usize>,
    image_access_rights: HashMap<String, Vec<AccessRight>>, // image_name -> access rights

    // UI flags
    show_add_image_dialog: bool,
    show_view_sharing_dialog: bool,

    image_textures: HashMap<String, egui::TextureHandle>,

    discovered_users: Vec<(String, String)>, // (username, ip)
    selected_user: Option<String>,
    user_images: HashMap<String, Vec<ImageInfo>>, // username -> images
    discover_loading: bool,
    discover_error: Option<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            username: "client1".to_string(),
            client_ip: "10.185.59.183".to_string(),
            client_port: 8080,
            middleware_addr: "127.0.0.1:9000".to_string(),
            connection_status: ConnectionStatus::Disconnected,
            heartbeat_active: false,
            add_image_path: String::new(),
            add_image_error: None,
            registration_error: None,
            status_message: "Not connected".to_string(),
            active_tab: ActiveTab::MyImages,
            my_images: Vec::new(),
            selected_image: None,
            image_access_rights: HashMap::new(),
            show_add_image_dialog: false,
            show_view_sharing_dialog: false,
            image_textures: HashMap::new(),
            discovered_users: Vec::new(),
            selected_user: None,
            user_images: HashMap::new(),
            discover_loading: false,
            discover_error: None,
        }
    }
}

// =======================================
// Main Application
// =======================================

struct CloudP2PApp {
    state: Arc<Mutex<AppState>>,
    middleware_started: bool,
}

impl Clone for CloudP2PApp {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            middleware_started: self.middleware_started,
        }
    }
}
impl CloudP2PApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Configure fonts and style
        configure_fonts(&cc.egui_ctx);

        Self {
            state: Arc::new(Mutex::new(AppState::default())),
            middleware_started: false,
        }
    }

    fn fetch_user_images(&self, username: &str) {
        let state = Arc::clone(&self.state);
        let username = username.to_string();
        let middleware_addr = {
            let s = state.lock().unwrap();
            s.middleware_addr.clone()
        };

        // Set selected user
        {
            let mut s = state.lock().unwrap();
            s.selected_user = Some(username.clone());
            s.status_message = format!("Fetching images for {}...", username);
            // Clear previous images
            s.user_images.remove(&username);
        }

        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            use std::net::TcpStream;

            let request_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let request = serde_json::json!({
                "FetchUserImages": {
                    "request_id": request_id,
                    "target_username": username,
                }
            });

            match TcpStream::connect(&middleware_addr) {
                Ok(stream) => {
                    let mut reader = BufReader::new(&stream);
                    let mut writer = stream.try_clone().unwrap();

                    let request_json = serde_json::to_string(&request).unwrap();
                    writer.write_all(request_json.as_bytes()).unwrap();
                    writer.write_all(b"\n").unwrap();
                    writer.flush().unwrap();

                    // Wait for response
                    std::thread::sleep(std::time::Duration::from_secs(2));

                    let mut response_line = String::new();
                    if let Err(e) = reader.read_line(&mut response_line) {
                        let mut s = state.lock().unwrap();
                        s.status_message = format!("Failed to read response: {}", e);
                        return;
                    }

                    match serde_json::from_str::<serde_json::Value>(&response_line.trim()) {
                        Ok(response) => {
                            let status = response["status"].as_str().unwrap_or("ERROR");
                            if status == "OK" {
                                if let Some(output_path) = response["output_path"].as_str() {
                                    // Parse JSON with image details
                                    if let Ok(json) =
                                        serde_json::from_str::<serde_json::Value>(output_path)
                                    {
                                        if let Some(images_array) = json["images"].as_array() {
                                            let mut images = Vec::new();
                                            for img in images_array {
                                                let name = img["image_name"]
                                                    .as_str()
                                                    .unwrap_or("unknown")
                                                    .to_string();
                                                let size =
                                                    img["size"].as_u64().unwrap_or(0) as usize;
                                                let path =
                                                    img["path"].as_str().unwrap_or("").to_string();

                                                images.push(ImageInfo {
                                                    name,
                                                    size,
                                                    path,
                                                    shared_count: 0,
                                                });
                                            }

                                            let mut s = state.lock().unwrap();
                                            s.user_images.insert(username.clone(), images.clone());
                                            s.status_message = format!(
                                                "✓ Loaded {} images from {}",
                                                images.len(),
                                                username
                                            );
                                        }
                                    }
                                }
                            } else {
                                let mut s = state.lock().unwrap();
                                s.status_message = format!(
                                    "Error: {}",
                                    response["message"].as_str().unwrap_or("Unknown")
                                );
                                s.user_images.insert(username.clone(), Vec::new());
                            }
                        }
                        Err(e) => {
                            let mut s = state.lock().unwrap();
                            s.status_message = format!("Failed to parse response: {}", e);
                        }
                    }
                }
                Err(e) => {
                    let mut s = state.lock().unwrap();
                    s.status_message = format!("Cannot connect to middleware: {}", e);
                }
            }
        });
    }

    fn fetch_active_users(&self) {
        let state = Arc::clone(&self.state);
        let middleware_addr = {
            let s = state.lock().unwrap();
            s.middleware_addr.clone()
        };

        println!("[GUI] Fetching active users from: {}", middleware_addr);

        // Set loading state
        {
            let mut s = state.lock().unwrap();
            s.discover_loading = true;
            s.discover_error = None;
            s.status_message = "Fetching active users...".to_string();
        }

        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            use std::net::TcpStream;

            let request_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let request = serde_json::json!({
                "FetchActiveUsers": {
                    "request_id": request_id,
                }
            });

            println!("[GUI] Connecting to middleware...");

            match TcpStream::connect(&middleware_addr) {
                Ok(stream) => {
                    println!("[GUI] Connected! Sending request...");

                    let mut reader = BufReader::new(&stream);
                    let mut writer = stream.try_clone().unwrap();

                    let request_json = serde_json::to_string(&request).unwrap();
                    println!("[GUI] Request: {}", request_json);

                    if let Err(e) = writer.write_all(request_json.as_bytes()) {
                        println!("[GUI] Failed to send request: {}", e);
                        let mut s = state.lock().unwrap();
                        s.discover_loading = false;
                        s.discover_error = Some(format!("Failed to send request: {}", e));
                        return;
                    }
                    writer.write_all(b"\n").unwrap();
                    writer.flush().unwrap();
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    println!("[GUI] Waiting for response...");

                    let mut response_line = String::new();
                    if let Err(e) = reader.read_line(&mut response_line) {
                        println!("[GUI] Failed to read response: {}", e);
                        let mut s = state.lock().unwrap();
                        s.discover_loading = false;
                        s.discover_error = Some(format!("Failed to read response: {}", e));
                        return;
                    }

                    println!("[GUI] Response: {}", response_line);

                    match serde_json::from_str::<serde_json::Value>(&response_line.trim()) {
                        Ok(response) => {
                            let status = response["status"].as_str().unwrap_or("ERROR");
                            println!("[GUI] Status: {}", status);

                            if status == "OK" {
                                if let Some(message) = response["message"].as_str() {
                                    println!("[GUI] Message: {}", message);

                                    // Parse users from message format: "username - ip"
                                    let mut users = Vec::new();
                                    for line in message.lines() {
                                        let line = line.trim();
                                        if line.is_empty() {
                                            continue;
                                        }

                                        let parts: Vec<&str> = line.split(" - ").collect();
                                        println!(
                                            "[GUI] Parsing line: '{}' -> parts: {:?}",
                                            line, parts
                                        );

                                        if parts.len() == 2 {
                                            users.push((
                                                parts[0].trim().to_string(),
                                                parts[1].trim().to_string(),
                                            ));
                                        }
                                    }

                                    println!("[GUI] Parsed {} users: {:?}", users.len(), users);

                                    let mut s = state.lock().unwrap();
                                    s.discovered_users = users;
                                    s.discover_loading = false;
                                    s.status_message =
                                        format!("✓ Found {} users", s.discovered_users.len());
                                }
                            } else {
                                let error_msg = response["message"]
                                    .as_str()
                                    .unwrap_or("Unknown error")
                                    .to_string();
                                println!("[GUI] Error from server: {}", error_msg);

                                let mut s = state.lock().unwrap();
                                s.discover_loading = false;
                                s.discover_error = Some(error_msg);
                            }
                        }
                        Err(e) => {
                            println!("[GUI] Failed to parse JSON: {}", e);
                            let mut s = state.lock().unwrap();
                            s.discover_loading = false;
                            s.discover_error = Some(format!("Invalid response: {}", e));
                        }
                    }
                }
                Err(e) => {
                    println!("[GUI] Connection failed: {}", e);
                    let mut s = state.lock().unwrap();
                    s.discover_loading = false;
                    s.discover_error = Some(format!("Cannot connect to middleware: {}", e));
                }
            }
        });
    }

    fn render_discovered_image_card(&self, ui: &mut egui::Ui, image: &ImageInfo, owner: &str) {
        let card_size = egui::vec2(120.0, 150.0);
        let (rect, response) = ui.allocate_exact_size(card_size, egui::Sense::click());

        // Draw card background
        let fill_color = if response.hovered() {
            ui.visuals().widgets.hovered.bg_fill
        } else {
            ui.visuals().widgets.inactive.bg_fill
        };

        ui.painter().rect_filled(rect, 5.0, fill_color);

        // Content layout
        let mut content_rect = rect;
        content_rect = content_rect.shrink(8.0);

        // Image area (placeholder for now)
        let image_rect =
            egui::Rect::from_min_size(content_rect.min, egui::vec2(content_rect.width(), 80.0));

        // Try to load texture
        let state = self.state.lock().unwrap();
        if let Some(texture) = state.image_textures.get(&image.name) {
            let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
            ui.painter()
                .image(texture.id(), image_rect, uv, egui::Color32::WHITE);
        } else {
            ui.painter()
                .rect_filled(image_rect, 3.0, egui::Color32::from_gray(60));
            ui.painter().text(
                image_rect.center(),
                egui::Align2::CENTER_CENTER,
                "🖼️",
                egui::FontId::proportional(30.0),
                egui::Color32::from_gray(150),
            );

            // Trigger loading
            drop(state);
            let ctx = ui.ctx().clone();
            let image_name = image.name.clone();
            let image_path = image.path.clone();
            let self_clone = Arc::new(self.clone());

            std::thread::spawn(move || {
                self_clone.load_image_texture(&ctx, &image_name, &image_path);
                ctx.request_repaint();
            });
        }

        // Image info text
        let text_y = image_rect.max.y + 5.0;
        let name_pos = egui::pos2(content_rect.min.x, text_y);
        ui.painter().text(
            name_pos,
            egui::Align2::LEFT_TOP,
            &image.name,
            egui::FontId::proportional(11.0),
            ui.visuals().text_color(),
        );

        let size_text = format_size(image.size);
        let size_pos = egui::pos2(content_rect.min.x, text_y + 15.0);
        ui.painter().text(
            size_pos,
            egui::Align2::LEFT_TOP,
            &size_text,
            egui::FontId::proportional(9.0),
            ui.visuals().weak_text_color(),
        );

        // Handle click - request access
        if response.clicked() {
            println!("[GUI] Clicked on {}'s image: {}", owner, image.name);
            // TODO: Open dialog to request access with number of views
            let mut state = self.state.lock().unwrap();
            state.status_message = format!(
                "Request access feature coming soon for {}'s {}",
                owner, image.name
            );
        }
    }

    fn load_image_texture(&self, ctx: &egui::Context, image_name: &str, image_path: &str) {
        let mut state = self.state.lock().unwrap();

        // Don't reload if already loaded
        if state.image_textures.contains_key(image_name) {
            return;
        }

        // Try to load the image
        if let Ok(image) = image::io::Reader::open(image_path) {
            if let Ok(dynamic_image) = image.decode() {
                let size = [
                    dynamic_image.width() as usize,
                    dynamic_image.height() as usize,
                ];
                let image_buffer = dynamic_image.to_rgba8();
                let pixels = image_buffer.as_flat_samples();

                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());

                let texture =
                    ctx.load_texture(image_name, color_image, egui::TextureOptions::LINEAR);

                state.image_textures.insert(image_name.to_string(), texture);
            }
        }
    }

    fn start_middleware(&mut self) {
        if self.middleware_started {
            return;
        }

        let state = Arc::clone(&self.state);

        // Get configuration from state
        let (middleware_ip, middleware_port, server_urls) = {
            let state = state.lock().unwrap();
            let parts: Vec<&str> = state.middleware_addr.split(':').collect();
            let ip = parts[0].to_string();
            let port = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(9000);

            let server_urls = vec![
                "http://10.185.59.183:8000".to_string(),
                "http://10.185.59.251:8000".to_string(),
            ];

            (ip, port, server_urls)
        };

        // Start middleware in background thread
        thread::spawn(move || {
            let middleware = ClientMiddleware::new(&middleware_ip, middleware_port, server_urls);
            if let Err(e) = middleware.start() {
                eprintln!("[GUI] Middleware error: {}", e);
                let mut state = state.lock().unwrap();
                state.connection_status =
                    ConnectionStatus::Error(format!("Middleware error: {}", e));
            }
        });

        // Give middleware time to start
        thread::sleep(Duration::from_millis(200));

        self.middleware_started = true;

        let mut state = self.state.lock().unwrap();
        state.status_message = "Middleware started".to_string();
    }

    fn register_client(&self) {
        let state = Arc::clone(&self.state);

        // Get registration info
        let (username, ip, middleware_addr) = {
            let state = state.lock().unwrap();
            (
                state.username.clone(),
                state.client_ip.clone(),
                state.middleware_addr.clone(),
            )
        };

        // Update status to connecting
        {
            let mut state = state.lock().unwrap();
            state.connection_status = ConnectionStatus::Connecting;
            state.registration_error = None;
            state.status_message = "Registering with directory service...".to_string();
        }

        // Perform registration in background thread
        thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            use std::net::TcpStream;

            // Create registration request
            let request = serde_json::json!({
                "RegisterWithDirectory": {
                    "request_id": 1,
                    "username": username,
                    "ip": ip,
                }
            });

            // Connect to middleware
            match TcpStream::connect(&middleware_addr) {
                Ok(stream) => {
                    let mut reader = BufReader::new(&stream);
                    let mut writer = stream.try_clone().unwrap();

                    // Send request
                    let request_json = serde_json::to_string(&request).unwrap();
                    if let Err(e) = writer.write_all(request_json.as_bytes()) {
                        let mut state = state.lock().unwrap();
                        state.connection_status =
                            ConnectionStatus::Error(format!("Send error: {}", e));
                        state.registration_error = Some(format!("Failed to send: {}", e));
                        return;
                    }
                    if let Err(e) = writer.write_all(b"\n") {
                        let mut state = state.lock().unwrap();
                        state.connection_status =
                            ConnectionStatus::Error(format!("Send error: {}", e));
                        state.registration_error = Some(format!("Failed to send: {}", e));
                        return;
                    }
                    writer.flush().unwrap();

                    // Read response
                    let mut response_line = String::new();
                    if let Err(e) = reader.read_line(&mut response_line) {
                        let mut state = state.lock().unwrap();
                        state.connection_status =
                            ConnectionStatus::Error(format!("Read error: {}", e));
                        state.registration_error = Some(format!("Failed to read response: {}", e));
                        return;
                    }

                    // Parse response
                    match serde_json::from_str::<serde_json::Value>(&response_line.trim()) {
                        Ok(response) => {
                            let status = response["status"].as_str().unwrap_or("ERROR");
                            let message = response["message"].as_str().unwrap_or("Unknown");

                            let mut state = state.lock().unwrap();
                            if status == "OK" {
                                state.connection_status = ConnectionStatus::Connected;
                                state.status_message = format!("✓ {}", message);
                                state.heartbeat_active = true;

                                // Start heartbeat
                                start_heartbeat(username.clone(), middleware_addr.clone());
                            } else {
                                state.connection_status =
                                    ConnectionStatus::Error(message.to_string());
                                state.registration_error = Some(message.to_string());
                                state.status_message = format!("✗ {}", message);
                            }
                        }
                        Err(e) => {
                            let mut state = state.lock().unwrap();
                            state.connection_status =
                                ConnectionStatus::Error(format!("Parse error: {}", e));
                            state.registration_error = Some(format!("Invalid response: {}", e));
                        }
                    }
                }
                Err(e) => {
                    let mut state = state.lock().unwrap();
                    state.connection_status =
                        ConnectionStatus::Error(format!("Connection failed: {}", e));
                    state.registration_error = Some(format!("Cannot connect to middleware: {}", e));
                    state.status_message = format!("✗ Connection failed: {}", e);
                }
            }
        });
    }

    // =======================================
    // UI Rendering Methods (moved to CloudP2PApp impl)
    // =======================================

    fn render_registration_form(&self, ui: &mut egui::Ui, state: &AppState) {
        ui.add_space(20.0);

        // Connection form
        egui::Frame::none()
            .fill(ui.visuals().faint_bg_color)
            .inner_margin(20.0)
            .rounding(5.0)
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading("Welcome to Cloud P2P");
                    ui.add_space(10.0);

                    match state.connection_status {
                        ConnectionStatus::Disconnected => {
                            ui.label("Please register to start sharing images");
                        }
                        ConnectionStatus::Connected => {
                            ui.colored_label(
                                egui::Color32::GREEN,
                                "✓ Successfully registered with directory service",
                            );
                        }
                        ConnectionStatus::Connecting => {
                            ui.label("Connecting to directory service...");
                            // spinner may not exist in older egui versions; keep as-is or remove if compile error
                            // ui.add(egui::Spinner::new());
                        }
                        ConnectionStatus::Error(_) => {
                            ui.colored_label(egui::Color32::RED, "✗ Registration failed");
                        }
                    }
                });

                ui.add_space(20.0);
                ui.separator();
                ui.add_space(20.0);

                // Configuration form
                egui::Grid::new("config_grid")
                    .num_columns(2)
                    .spacing([20.0, 10.0])
                    .show(ui, |ui| {
                        // Username
                        ui.label("Username:");
                        {
                            let mut username = state.username.clone();
                            let username_enabled = matches!(
                                state.connection_status,
                                ConnectionStatus::Disconnected | ConnectionStatus::Error(_)
                            );
                            ui.add_enabled(
                                username_enabled,
                                egui::TextEdit::singleline(&mut username).desired_width(200.0),
                            );
                            if username != state.username {
                                self.state.lock().unwrap().username = username;
                            }
                        }
                        ui.end_row();

                        // Client IP
                        ui.label("Client IP:");
                        {
                            let mut client_ip = state.client_ip.clone();
                            let ip_enabled = matches!(
                                state.connection_status,
                                ConnectionStatus::Disconnected | ConnectionStatus::Error(_)
                            );
                            ui.add_enabled(
                                ip_enabled,
                                egui::TextEdit::singleline(&mut client_ip).desired_width(200.0),
                            );
                            if client_ip != state.client_ip {
                                self.state.lock().unwrap().client_ip = client_ip;
                            }
                        }
                        ui.end_row();

                        // Client Port
                        ui.label("Client Port:");
                        {
                            let mut port = state.client_port.to_string();
                            let port_enabled = matches!(
                                state.connection_status,
                                ConnectionStatus::Disconnected | ConnectionStatus::Error(_)
                            );
                            ui.add_enabled(
                                port_enabled,
                                egui::TextEdit::singleline(&mut port).desired_width(200.0),
                            );
                            if let Ok(new_port) = port.parse::<u16>() {
                                if new_port != state.client_port {
                                    self.state.lock().unwrap().client_port = new_port;
                                }
                            }
                        }
                        ui.end_row();

                        // Middleware (read-only)
                        ui.label("Middleware:");
                        ui.label(&state.middleware_addr);
                        ui.end_row();
                    });

                ui.add_space(20.0);

                // Error message
                if let Some(error) = &state.registration_error {
                    ui.colored_label(egui::Color32::RED, format!("Error: {}", error));
                    ui.add_space(10.0);
                }

                // Register button
                ui.vertical_centered(|ui| {
                    let button_enabled = matches!(
                        state.connection_status,
                        ConnectionStatus::Disconnected | ConnectionStatus::Error(_)
                    );

                    let button = egui::Button::new("🔗 Register with Directory Service")
                        .min_size(egui::vec2(250.0, 40.0));

                    if ui.add_enabled(button_enabled, button).clicked() {
                        self.register_client();
                    }
                });
            });

        ui.add_space(20.0);

        // Info section
        ui.collapsing("ℹ️ Connection Info", |ui| {
            ui.label(format!("Middleware Address: {}", state.middleware_addr));
            ui.label("Server URLs:");
            ui.label("  • http://10.185.59.183:8000");
            ui.label("  • http://10.185.59.251:8000");
        });
    }

    fn render_tabs(&self, ui: &mut egui::Ui) {
        // Acquire lock once to modify active_tab via selectable_value
        let mut guard = self.state.lock().unwrap();
        let state_clone = guard.clone();

        // Tab bar: operate on guard so selectable_value can mutate active_tab
        ui.horizontal(|ui| {
            ui.selectable_value(&mut guard.active_tab, ActiveTab::MyImages, "📁 My Images");
            ui.selectable_value(&mut guard.active_tab, ActiveTab::Discover, "🔍 Discover");
            ui.selectable_value(&mut guard.active_tab, ActiveTab::Requests, "📬 Requests");
        });
        drop(guard); // ✅ Release lock before rendering content

        ui.separator();
        ui.add_space(10.0);

        // Tab content
        match state_clone.active_tab {
            ActiveTab::MyImages => {
                // ✅ Don't pass state, let the function get its own lock
                self.render_my_images_tab(ui, &state_clone);
            }
            ActiveTab::Discover => self.render_discover_tab(ui),
            ActiveTab::Requests => self.render_requests_tab(ui),
        }
    }

    fn render_my_images_tab(&self, ui: &mut egui::Ui, state: &AppState) {
        ui.horizontal(|ui| {
            ui.heading("My Uploaded Images");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("➕ Add Image").clicked() {
                    self.state.lock().unwrap().show_add_image_dialog = true;
                }
            });
        });

        ui.add_space(10.0);

        if state.my_images.is_empty() {
            // Empty state
            ui.vertical_centered(|ui| {
                ui.add_space(50.0);
                ui.label("📂 No images uploaded yet");
                ui.add_space(10.0);
                ui.label("Click 'Add Image' to upload your first image");
                ui.add_space(20.0);

                if ui.button("➕ Add Image").clicked() {
                    self.state.lock().unwrap().show_add_image_dialog = true;
                }
            });
        } else {
            // ✅ Track which image was clicked
            let mut clicked_idx: Option<usize> = None;

            // Image grid
            egui::ScrollArea::vertical().show(ui, |ui| {
                let available_width = ui.available_width();
                let image_width = 150.0;
                let spacing = 15.0;
                let columns =
                    ((available_width + spacing) / (image_width + spacing)).floor() as usize;
                let columns = columns.max(1);

                egui::Grid::new("images_grid")
                    .spacing([spacing, spacing])
                    .show(ui, |ui| {
                        for (idx, image) in state.my_images.iter().enumerate() {
                            if idx > 0 && idx % columns == 0 {
                                ui.end_row();
                            }

                            // ✅ Check if this card was clicked
                            let was_clicked = self.render_image_card(
                                ui,
                                image,
                                idx,
                                state.selected_image == Some(idx),
                            );

                            if was_clicked {
                                clicked_idx = Some(idx);
                            }
                        }
                    });

                ui.add_space(20.0);

                // Selected image details
                if let Some(selected_idx) = state.selected_image {
                    if let Some(selected_image) = state.my_images.get(selected_idx) {
                        ui.separator();
                        ui.add_space(10.0);

                        ui.heading(format!("Selected: {}", selected_image.name));
                        ui.add_space(10.0);

                        // Access rights section
                        egui::Frame::none()
                            .fill(ui.visuals().faint_bg_color)
                            .inner_margin(15.0)
                            .rounding(5.0)
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("Current Access Rights").strong());
                                ui.add_space(5.0);

                                if let Some(access_list) =
                                    state.image_access_rights.get(&selected_image.name)
                                {
                                    if access_list.is_empty() {
                                        ui.label("No users have access yet");
                                    } else {
                                        for access in access_list {
                                            ui.horizontal(|ui| {
                                                ui.label("•");
                                                ui.label(&access.viewer);
                                                ui.label("-");
                                                let remaining = access
                                                    .accepted_views
                                                    .saturating_sub(access.views_used);
                                                ui.label(format!(
                                                    "{} / {} views remaining",
                                                    remaining, access.accepted_views
                                                ));
                                            });
                                        }
                                    }
                                } else {
                                    ui.label("No users have access yet");
                                }

                                ui.add_space(10.0);

                                ui.horizontal(|ui| {
                                    if ui.button("👁️ View Sharing").clicked() {
                                        self.state.lock().unwrap().show_view_sharing_dialog = true;
                                    }

                                    if ui.button("🗑️ Delete Image").clicked() {
                                        self.state.lock().unwrap().status_message =
                                            "Delete not yet implemented".to_string();
                                    }
                                });
                            });
                    }
                }
            });

            // ✅ Update selected_image AFTER the UI is done rendering
            if let Some(idx) = clicked_idx {
                self.state.lock().unwrap().selected_image = Some(idx);
            }
        }
    }
    fn render_image_card(
        &self,
        ui: &mut egui::Ui,
        image: &ImageInfo,
        idx: usize,
        is_selected: bool,
    ) -> bool {
        // ← Return bool indicating if clicked
        let card_size = egui::vec2(150.0, 180.0);

        let (rect, response) = ui.allocate_exact_size(card_size, egui::Sense::click());

        // Draw card background
        let fill_color = if is_selected {
            ui.visuals().selection.bg_fill
        } else if response.hovered() {
            ui.visuals().widgets.hovered.bg_fill
        } else {
            ui.visuals().widgets.inactive.bg_fill
        };

        ui.painter().rect_filled(rect, 5.0, fill_color);

        // Draw border if selected
        if is_selected {
            ui.painter().rect_stroke(
                rect,
                5.0,
                egui::Stroke::new(2.0, ui.visuals().selection.stroke.color),
            );
        }

        // Content layout
        let mut content_rect = rect;
        content_rect = content_rect.shrink(10.0);

        // Image area
        let image_rect =
            egui::Rect::from_min_size(content_rect.min, egui::vec2(content_rect.width(), 100.0));

        // Try to load texture if not already loaded
        let state = self.state.lock().unwrap();
        if let Some(texture) = state.image_textures.get(&image.name) {
            // Draw the actual image texture
            let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
            ui.painter()
                .image(texture.id(), image_rect, uv, egui::Color32::WHITE);
        } else {
            // Draw placeholder while loading
            ui.painter()
                .rect_filled(image_rect, 3.0, egui::Color32::from_gray(60));
            ui.painter().text(
                image_rect.center(),
                egui::Align2::CENTER_CENTER,
                "🖼️",
                egui::FontId::proportional(40.0),
                egui::Color32::from_gray(150),
            );

            // Trigger loading in background
            drop(state);
            let ctx = ui.ctx().clone();
            let image_name = image.name.clone();
            let image_path = image.path.clone();
            let self_clone = Arc::new(self.clone());

            std::thread::spawn(move || {
                self_clone.load_image_texture(&ctx, &image_name, &image_path);
                ctx.request_repaint();
            });
        }

        // Image info
        let text_y = image_rect.max.y + 5.0;
        let name_pos = egui::pos2(content_rect.min.x, text_y);
        ui.painter().text(
            name_pos,
            egui::Align2::LEFT_TOP,
            &image.name,
            egui::FontId::proportional(13.0),
            ui.visuals().text_color(),
        );

        let size_text = format_size(image.size);
        let size_pos = egui::pos2(content_rect.min.x, text_y + 18.0);
        ui.painter().text(
            size_pos,
            egui::Align2::LEFT_TOP,
            &size_text,
            egui::FontId::proportional(11.0),
            ui.visuals().weak_text_color(),
        );

        let shared_text = format!("Shared: {}", image.shared_count);
        let shared_pos = egui::pos2(content_rect.min.x, text_y + 35.0);
        ui.painter().text(
            shared_pos,
            egui::Align2::LEFT_TOP,
            &shared_text,
            egui::FontId::proportional(11.0),
            ui.visuals().weak_text_color(),
        );

        // Return whether it was clicked (don't lock here!)
        response.clicked()
    }

    fn render_discover_tab(&self, ui: &mut egui::Ui) {
        ui.heading("🔍 Discover Images");
        ui.add_space(10.0);

        // Get current state snapshot
        let state = self.state.lock().unwrap().clone();

        // Fetch users button
        ui.horizontal(|ui| {
            let button_enabled = !state.discover_loading;
            if ui
                .add_enabled(button_enabled, egui::Button::new("🔄 Refresh Users"))
                .clicked()
            {
                self.fetch_active_users();
            }

            if state.discover_loading {
                ui.spinner();
                ui.label("Loading...");
            }
        });

        ui.add_space(10.0);

        // Show error if any
        if let Some(error) = &state.discover_error {
            ui.colored_label(egui::Color32::RED, format!("Error: {}", error));
            ui.add_space(10.0);
        }

        // Two-column layout: users on left, images on right
        ui.columns(2, |columns| {
            // Left column: User list
            columns[0].heading("Online Users");
            columns[0].add_space(5.0);

            // ✅ FIX: Add unique ID to first ScrollArea
            egui::ScrollArea::vertical()
                .id_source("discover_users_scroll") // ← ADD THIS
                .max_height(400.0)
                .show(&mut columns[0], |ui| {
                    if state.discovered_users.is_empty() {
                        ui.label("No users discovered yet.");
                        ui.label("Click 'Refresh Users' to discover online users.");
                    } else {
                        for (username, ip) in &state.discovered_users {
                            // Skip our own username
                            if username == &state.username {
                                continue;
                            }

                            let is_selected = state.selected_user.as_ref() == Some(username);

                            let button = egui::Button::new(format!("👤 {}", username))
                                .min_size(egui::vec2(150.0, 30.0));

                            let response = if is_selected {
                                ui.add(button.fill(ui.visuals().selection.bg_fill))
                            } else {
                                ui.add(button)
                            };

                            if response.clicked() {
                                // Fetch images for this user
                                self.fetch_user_images(username);
                            }

                            ui.small(format!("IP: {}", ip));
                            ui.add_space(5.0);
                        }
                    }
                });

            // Right column: User's images
            columns[1].heading(if let Some(user) = &state.selected_user {
                format!("{}'s Images", user)
            } else {
                "Select a user to view images".to_string()
            });
            columns[1].add_space(5.0);

            // ✅ FIX: Add unique ID to second ScrollArea
            egui::ScrollArea::vertical()
                .id_source("discover_images_scroll") // ← ADD THIS
                .max_height(400.0)
                .show(&mut columns[1], |ui| {
                    if let Some(selected_user) = &state.selected_user {
                        if let Some(images) = state.user_images.get(selected_user) {
                            if images.is_empty() {
                                ui.label(format!("{} has no images yet.", selected_user));
                            } else {
                                // Display images in a grid
                                let available_width = ui.available_width();
                                let image_width = 120.0;
                                let spacing = 10.0;
                                let columns_count =
                                    ((available_width + spacing) / (image_width + spacing)).floor()
                                        as usize;
                                let columns_count = columns_count.max(1);

                                egui::Grid::new("discover_images_grid")
                                    .spacing([spacing, spacing])
                                    .show(ui, |ui| {
                                        for (idx, image) in images.iter().enumerate() {
                                            if idx > 0 && idx % columns_count == 0 {
                                                ui.end_row();
                                            }

                                            self.render_discovered_image_card(
                                                ui,
                                                image,
                                                selected_user,
                                            );
                                        }
                                    });
                            }
                        } else {
                            ui.label("Loading images...");
                            ui.spinner();
                        }
                    } else {
                        ui.vertical_centered(|ui| {
                            ui.add_space(50.0);
                            ui.label("👈 Select a user from the list");
                        });
                    }
                });
        });
    }

    fn render_requests_tab(&self, ui: &mut egui::Ui) {
        ui.heading("📬 Access Requests");
        ui.add_space(20.0);
        ui.vertical_centered(|ui| {
            ui.label("(Coming soon...)");
        });
    }

    // =======================================
    // Action Methods
    // =======================================

    fn render_add_image_dialog(&self, ctx: &egui::Context) {
        let mut state = self.state.lock().unwrap();

        if !state.show_add_image_dialog {
            return;
        }

        let mut open = true;

        egui::Window::new("Add Image")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(400.0);

                ui.heading("Upload New Image");
                ui.add_space(10.0);

                // Error message
                if let Some(error) = &state.add_image_error {
                    ui.colored_label(egui::Color32::RED, format!("Error: {}", error));
                    ui.add_space(10.0);
                }

                // Image path input
                ui.horizontal(|ui| {
                    ui.label("Image Path:");
                    ui.text_edit_singleline(&mut state.add_image_path);
                });

                ui.add_space(5.0);
                ui.label(
                    egui::RichText::new("Enter the full path to your image file")
                        .small()
                        .weak(),
                );
                ui.add_space(10.0);

                ui.separator();
                ui.add_space(10.0);

                // Buttons
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        state.show_add_image_dialog = false;
                        state.add_image_path.clear();
                        state.add_image_error = None;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let can_submit = !state.add_image_path.is_empty();

                        if ui
                            .add_enabled(can_submit, egui::Button::new("Upload"))
                            .clicked()
                        {
                            // Check if file exists BEFORE clearing the path
                            if !std::path::Path::new(&state.add_image_path).exists() {
                                state.add_image_error = Some("File not found".to_string());
                            } else {
                                // Clear error and close dialog
                                state.add_image_error = None;
                                state.show_add_image_dialog = false;
                                // Don't clear the path yet - we need it for upload!
                                state.status_message = "Uploading image...".to_string();
                            }
                        }
                    });
                });
            });

        // Check if upload should be triggered (after the window is closed)
        let should_upload = state.status_message == "Uploading image...";
        let path = state.add_image_path.clone(); // Clone BEFORE clearing
        let username = state.username.clone();
        let middleware_addr = state.middleware_addr.clone();

        // Handle close button
        if !open {
            state.show_add_image_dialog = false;
            state.add_image_path.clear();
            state.add_image_error = None;
        }

        // Clear the path now if we're uploading
        if should_upload {
            state.add_image_path.clear();
        }

        // Drop the lock before spawning thread
        drop(state);

        // Perform upload in background thread if triggered
        if should_upload {
            let state_clone = Arc::clone(&self.state);
            std::thread::spawn(move || {
                upload_image(path, username, middleware_addr, state_clone);
            });
        }
    }
}

fn upload_image(
    image_path: String,
    username: String,
    middleware_addr: String,
    state: Arc<Mutex<AppState>>,
) {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;

    println!("[GUI] Uploading image: {}", image_path);

    // Extract image name from path
    let image_name = std::path::Path::new(&image_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Read and resize image to 100x100
    match resize_image_to_100x100(&image_path) {
        Ok(resized_bytes) => {
            // Create request
            let request_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let request = serde_json::json!({
                "AddImage": {
                    "request_id": request_id,
                    "username": username,
                    "image_name": image_name,
                    "image_bytes": resized_bytes,
                }
            });

            // Connect to middleware
            match TcpStream::connect(&middleware_addr) {
                Ok(stream) => {
                    let mut reader = BufReader::new(&stream);
                    let mut writer = stream.try_clone().unwrap();

                    // Send request
                    let request_json = serde_json::to_string(&request).unwrap();
                    if let Err(e) = writer.write_all(request_json.as_bytes()) {
                        let mut state = state.lock().unwrap();
                        state.status_message = format!("Upload failed: {}", e);
                        return;
                    }
                    writer.write_all(b"\n").unwrap();
                    writer.flush().unwrap();

                    // Read response
                    let mut response_line = String::new();
                    if let Err(e) = reader.read_line(&mut response_line) {
                        let mut state = state.lock().unwrap();
                        state.status_message = format!("Upload failed: {}", e);
                        return;
                    }

                    // Parse response
                    match serde_json::from_str::<serde_json::Value>(&response_line.trim()) {
                        Ok(response) => {
                            let status = response["status"].as_str().unwrap_or("ERROR");
                            let message = response["message"].as_str().unwrap_or("Unknown");

                            let mut state = state.lock().unwrap();
                            if status == "OK" {
                                state.status_message = format!("✓ Image uploaded: {}", image_name);

                                // Add to my_images list with the ORIGINAL path (not resized)
                                state.my_images.push(ImageInfo {
                                    name: image_name.clone(),
                                    size: resized_bytes.len(),
                                    path: image_path, // Store original path for display
                                    shared_count: 0,
                                });
                            } else {
                                state.status_message = format!("Upload failed: {}", message);
                            }
                        }
                        Err(e) => {
                            let mut state = state.lock().unwrap();
                            state.status_message =
                                format!("Upload failed: Invalid response ({})", e);
                        }
                    }
                }
                Err(e) => {
                    let mut state: std::sync::MutexGuard<'_, AppState> = state.lock().unwrap();
                    state.status_message = format!("Cannot connect to middleware: {}", e);
                }
            }
        }
        Err(e) => {
            let mut state = state.lock().unwrap();
            state.status_message = format!("Error resizing image: {}", e);
        }
    }
}

fn resize_image_to_100x100(image_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use image::imageops::FilterType;
    use image::io::Reader as ImageReader;

    // Open the image
    let img = ImageReader::open(image_path)?.decode()?;

    // Resize to 100x100 using Lanczos3 filter (high quality)
    let resized = img.resize_exact(100, 100, FilterType::Lanczos3);

    // Encode as PNG
    let mut png_bytes = Vec::new();
    resized.write_to(
        &mut std::io::Cursor::new(&mut png_bytes),
        image::ImageFormat::Png,
    )?;

    Ok(png_bytes)
}
// =======================================
// eframe App impl
// =======================================

impl eframe::App for CloudP2PApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Request repaint for status updates
        ctx.request_repaint_after(Duration::from_secs(1));

        // Start middleware on first frame
        if !self.middleware_started {
            self.start_middleware();
        }

        let state = self.state.lock().unwrap().clone();

        // Top panel - Title bar
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(5.0);
            ui.horizontal(|ui| {
                ui.heading("🌐 Cloud P2P Image Sharing");
                ui.with_layout(
                    egui::Layout::right_to_left(egui::Align::Center),
                    |ui| match state.connection_status {
                        ConnectionStatus::Connected => {
                            ui.colored_label(egui::Color32::GREEN, "● Connected");
                        }
                        ConnectionStatus::Connecting => {
                            ui.colored_label(egui::Color32::YELLOW, "⏳ Connecting...");
                        }
                        ConnectionStatus::Disconnected => {
                            ui.colored_label(egui::Color32::GRAY, "○ Disconnected");
                        }
                        ConnectionStatus::Error(_) => {
                            ui.colored_label(egui::Color32::RED, "✗ Error");
                        }
                    },
                );
            });
            ui.add_space(5.0);
        });

        // Bottom panel - Status bar
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                ui.label(format!("Status: {}", state.status_message));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if state.heartbeat_active {
                        ui.label("💓 Heartbeat: Active");
                    }
                    ui.separator();
                    ui.label(format!("IP: {}", state.client_ip));
                });
            });
            ui.add_space(3.0);
        });

        // Central panel - Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            match state.connection_status {
                ConnectionStatus::Connected => {
                    // Show tabs when connected
                    self.render_tabs(ui);
                }
                _ => {
                    // Show registration form when not connected
                    self.render_registration_form(ui, &state);
                }
            }
        });
        self.render_add_image_dialog(ctx);
    }
}

// =======================================
// Helper Functions
// =======================================

fn format_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn configure_fonts(ctx: &egui::Context) {
    // Increase default font sizes
    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (
            egui::TextStyle::Heading,
            egui::FontId::new(24.0, egui::FontFamily::Proportional),
        ),
        (
            egui::TextStyle::Body,
            egui::FontId::new(14.0, egui::FontFamily::Proportional),
        ),
        (
            egui::TextStyle::Button,
            egui::FontId::new(14.0, egui::FontFamily::Proportional),
        ),
        (
            egui::TextStyle::Small,
            egui::FontId::new(12.0, egui::FontFamily::Proportional),
        ),
        (
            egui::TextStyle::Monospace,
            egui::FontId::new(12.0, egui::FontFamily::Monospace),
        ),
    ]
    .into();

    ctx.set_style(style);
}

fn start_heartbeat(username: String, middleware_addr: String) {
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(20));

            let request = serde_json::json!({
                "Heartbeat": {
                    "request_id": 999999,
                    "username": username,
                }
            });

            // Send heartbeat (silent, don't update UI on failure)
            if let Ok(stream) = std::net::TcpStream::connect(&middleware_addr) {
                use std::io::Write;
                let mut writer = stream;
                let request_json = serde_json::to_string(&request).unwrap();
                let _ = writer.write_all(request_json.as_bytes());
                let _ = writer.write_all(b"\n");
            }
        }
    });
}

// =======================================
// Main Entry Point
// =======================================

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(800.0, 600.0)),
        ..Default::default()
    };

    eframe::run_native(
        "Cloud P2P Image Sharing",
        options,
        Box::new(|cc| Box::new(CloudP2PApp::new(cc))),
    )
}
