// =======================================
// stress_test_client.rs
// Automated Stress Testing Client
// =======================================

mod client;
mod middleware;

use client::{Client, RequestStatus};
use middleware::ClientMiddleware;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// =======================================
// Metrics Module
// =======================================

mod metrics {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[derive(Debug, Clone)]
    pub struct RequestMetrics {
        pub request_id: u64,
        pub filename: String,
        pub start_time: Instant,
        pub end_time: Option<Instant>,
        pub success: bool,
        pub error_message: Option<String>,
    }

    impl RequestMetrics {
        pub fn new(request_id: u64, filename: String) -> Self {
            RequestMetrics {
                request_id,
                filename,
                start_time: Instant::now(),
                end_time: None,
                success: false,
                error_message: None,
            }
        }

        pub fn complete(&mut self, success: bool, error_message: Option<String>) {
            self.end_time = Some(Instant::now());
            self.success = success;
            self.error_message = error_message;
        }

        pub fn turnaround_time(&self) -> Option<Duration> {
            self.end_time.map(|end| end - self.start_time)
        }
    }

    pub struct MetricsCollector {
        metrics: Arc<Mutex<HashMap<u64, RequestMetrics>>>,
        start_time: Instant,
    }

    impl MetricsCollector {
        pub fn new() -> Self {
            MetricsCollector {
                metrics: Arc::new(Mutex::new(HashMap::new())),
                start_time: Instant::now(),
            }
        }

        pub fn start_request(&self, request_id: u64, filename: String) {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.insert(request_id, RequestMetrics::new(request_id, filename));
        }

        pub fn complete_request(&self, request_id: u64, success: bool, error_message: Option<String>) {
            let mut metrics = self.metrics.lock().unwrap();
            if let Some(metric) = metrics.get_mut(&request_id) {
                metric.complete(success, error_message);
            }
        }

        pub fn is_completed(&self, request_id: u64) -> bool {
            let metrics = self.metrics.lock().unwrap();
            if let Some(metric) = metrics.get(&request_id) {
                metric.end_time.is_some()
            } else {
                false
            }
        }

        pub fn print_summary(&self) {
            let metrics = self.metrics.lock().unwrap();
            let total_requests = metrics.len();
            
            if total_requests == 0 {
                println!("\n========================================");
                println!("No requests were processed");
                println!("========================================\n");
                return;
            }

            let successful = metrics.values().filter(|m| m.success).count();
            let failed = total_requests - successful;
            let success_rate = (successful as f64 / total_requests as f64) * 100.0;

            let turnaround_times: Vec<Duration> = metrics
                .values()
                .filter_map(|m| m.turnaround_time())
                .collect();

            let avg_turnaround = if !turnaround_times.is_empty() {
                let total_ms: u128 = turnaround_times.iter().map(|d| d.as_millis()).sum();
                total_ms as f64 / turnaround_times.len() as f64
            } else {
                0.0
            };

            let min_turnaround = turnaround_times
                .iter()
                .min()
                .map(|d| d.as_millis())
                .unwrap_or(0);

            let max_turnaround = turnaround_times
                .iter()
                .max()
                .map(|d| d.as_millis())
                .unwrap_or(0);

            let total_elapsed = self.start_time.elapsed();
            let throughput = successful as f64 / total_elapsed.as_secs_f64();

            println!("\n========================================");
            println!("STRESS TEST RESULTS");
            println!("========================================");
            println!("Total Requests:        {}", total_requests);
            println!("Successful:            {}", successful);
            println!("Failed:                {}", failed);
            println!("Success Rate:          {:.2}%", success_rate);
            println!("----------------------------------------");
            println!("Turnaround Time (Avg): {:.2} ms", avg_turnaround);
            println!("Turnaround Time (Min): {} ms", min_turnaround);
            println!("Turnaround Time (Max): {} ms", max_turnaround);
            println!("----------------------------------------");
            println!("Total Elapsed Time:    {:.2} seconds", total_elapsed.as_secs_f64());
            println!("Throughput:            {:.2} requests/second", throughput);
            println!("========================================\n");

            if failed > 0 {
                println!("Failed Requests:");
                println!("----------------------------------------");
                for metric in metrics.values().filter(|m| !m.success) {
                    println!(
                        "  #{} - {} - {}",
                        metric.request_id,
                        metric.filename,
                        metric.error_message.as_ref().unwrap_or(&"Unknown error".to_string())
                    );
                }
                println!();
            }
        }
    }
}

// =======================================
// File System Module
// =======================================

mod filesystem {
    use std::fs;
    use std::path::{Path, PathBuf};

    pub fn get_image_files(directory: &Path) -> Result<Vec<PathBuf>, String> {
        if !directory.exists() {
            return Err(format!("Directory does not exist: {}", directory.display()));
        }

        if !directory.is_dir() {
            return Err(format!("Path is not a directory: {}", directory.display()));
        }

        let valid_extensions = ["jpg", "jpeg", "png", "gif", "bmp"];
        let mut image_files = Vec::new();

        match fs::read_dir(directory) {
            Ok(entries) => {
                for entry in entries {
                    if let Ok(entry) = entry {
                        let path = entry.path();
                        if path.is_file() {
                            if let Some(ext) = path.extension() {
                                if let Some(ext_str) = ext.to_str() {
                                    if valid_extensions.contains(&ext_str.to_lowercase().as_str()) {
                                        image_files.push(path);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => return Err(format!("Failed to read directory: {}", e)),
        }

        if image_files.is_empty() {
            return Err("No image files found in directory".to_string());
        }

        image_files.sort();
        Ok(image_files)
    }

    pub fn create_output_directory(output_dir: &Path) -> Result<(), String> {
        if output_dir.exists() && !output_dir.is_dir() {
            return Err(format!(
                "Output path exists but is not a directory: {}",
                output_dir.display()
            ));
        }

        fs::create_dir_all(output_dir)
            .map_err(|e| format!("Failed to create output directory: {}", e))
    }

    pub fn save_encrypted_file(source: &Path, dest_dir: &Path) -> Result<PathBuf, String> {
        let filename = source
            .file_name()
            .ok_or("Invalid source filename")?;
        
        let dest_path = dest_dir.join(filename);
        
        fs::copy(source, &dest_path)
            .map_err(|e| format!("Failed to copy file: {}", e))?;
        
        Ok(dest_path)
    }
}

// =======================================
// Stress Test Runner Module
// =======================================

mod stress_test {
    use super::*;
    use crate::metrics::MetricsCollector;
    use crate::filesystem;

    pub struct StressTestRunner {
        client: Client,
        output_dir: PathBuf,
        metrics: MetricsCollector,
    }

    impl StressTestRunner {
        pub fn new(client: Client, output_dir: PathBuf) -> Self {
            StressTestRunner {
                client,
                output_dir,
                metrics: MetricsCollector::new(),
            }
        }

        pub fn run(&self, image_files: Vec<PathBuf>) {
            println!("\n========================================");
            println!("Starting stress test with {} images", image_files.len());
            println!("========================================\n");

            let request_ids = self.submit_requests(&image_files);
            self.monitor_completion(&request_ids);
            self.metrics.print_summary();
        }

        fn submit_requests(&self, image_files: &[PathBuf]) -> Vec<(u64, String)> {
            let mut request_ids = Vec::new();

            for (index, image_path) in image_files.iter().enumerate() {
                let filename = image_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string();

                println!("[StressTest] [{}/{}] Queuing: {}", 
                    index + 1, image_files.len(), filename);

                match self.client.request_encryption(image_path.to_str().unwrap()) {
                    Ok(request_id) => {
                        self.metrics.start_request(request_id, filename.clone());
                        request_ids.push((request_id, filename));
                    }
                    Err(e) => {
                        eprintln!("[StressTest] Failed to queue {}: {}", filename, e);
                    }
                }

                thread::sleep(Duration::from_millis(100));
            }

            println!("\n[StressTest] All {} requests queued. Monitoring completion...\n", 
                request_ids.len());
            
            request_ids
        }

        fn monitor_completion(&self, request_ids: &[(u64, String)]) {
            let timeout = Duration::from_secs(600);
            let start = Instant::now();
            let mut completed_count = 0;

            while completed_count < request_ids.len() && start.elapsed() < timeout {
                thread::sleep(Duration::from_secs(2));

                let (pending, in_progress) = self.count_request_states(request_ids);

                for (request_id, filename) in request_ids {
                    if self.metrics.is_completed(*request_id) {
                        continue;
                    }

                    match self.client.tracker.get_status(*request_id) {
                        Some(RequestStatus::Completed(ref response)) => {
                            if let Some(output_path) = &response.output_path {
                                match filesystem::save_encrypted_file(
                                    Path::new(output_path),
                                    &self.output_dir
                                ) {
                                    Ok(dest_path) => {
                                        println!(
                                            "[StressTest] ✓ Request #{}: {} → {}",
                                            request_id,
                                            filename,
                                            dest_path.display()
                                        );
                                        self.metrics.complete_request(*request_id, true, None);
                                    }
                                    Err(e) => {
                                        println!(
                                            "[StressTest] ⚠ Request #{}: {} completed but failed to save: {}",
                                            request_id, filename, e
                                        );
                                        self.metrics.complete_request(
                                            *request_id,
                                            false,
                                            Some(format!("Failed to save: {}", e))
                                        );
                                    }
                                }
                            } else {
                                println!(
                                    "[StressTest] ✓ Request #{}: {} (no output file)",
                                    request_id, filename
                                );
                                self.metrics.complete_request(*request_id, true, None);
                            }
                            completed_count += 1;
                        }
                        Some(RequestStatus::Failed(ref err)) => {
                            println!(
                                "[StressTest] ✗ Request #{}: {} - {}",
                                request_id, filename, err
                            );
                            self.metrics.complete_request(
                                *request_id,
                                false,
                                Some(err.clone())
                            );
                            completed_count += 1;
                        }
                        _ => {}
                    }
                }

                if completed_count < request_ids.len() {
                    println!(
                        "[StressTest] Progress: {}/{} completed | {} pending | {} in progress",
                        completed_count,
                        request_ids.len(),
                        pending,
                        in_progress
                    );
                }
            }

            if start.elapsed() >= timeout {
                println!("\n[StressTest] ⚠️ Timeout reached!");
                self.handle_timeout(request_ids);
            }

            println!("\n[StressTest] Processing completed!\n");
        }

        fn count_request_states(&self, request_ids: &[(u64, String)]) -> (usize, usize) {
            let mut pending = 0;
            let mut in_progress = 0;

            for (request_id, _) in request_ids {
                if self.metrics.is_completed(*request_id) {
                    continue;
                }

                match self.client.tracker.get_status(*request_id) {
                    Some(RequestStatus::Pending) => pending += 1,
                    Some(RequestStatus::InProgress) => in_progress += 1,
                    _ => {}
                }
            }

            (pending, in_progress)
        }

        fn handle_timeout(&self, request_ids: &[(u64, String)]) {
            for (request_id, _) in request_ids {
                if !self.metrics.is_completed(*request_id) {
                    self.metrics.complete_request(
                        *request_id,
                        false,
                        Some("Timeout".to_string())
                    );
                }
            }
        }
    }
}

// =======================================
// Configuration Module
// =======================================

mod config {
    use std::path::Path;

    pub struct Config {
        pub middleware_port: u16,
        pub input_dir: String,
        pub output_dir: String,
        pub username: String,
        pub client_ip: String,
        pub client_port: u16,
        pub middleware_ip: String,
        pub server_urls: Vec<String>,
    }

    impl Config {
        pub fn from_args(args: Vec<String>) -> Result<Self, String> {
            if args.len() != 4 {
                return Err(format!(
                    "Usage: {} <middleware_port> <input_directory> <output_directory>",
                    args[0]
                ));
            }

            let middleware_port: u16 = args[1]
                .parse()
                .map_err(|_| format!("Invalid port number: {}", args[1]))?;

            let input_dir = args[2].clone();
            let output_dir = args[3].clone();

            if !Path::new(&input_dir).exists() {
                return Err(format!("Input directory does not exist: {}", input_dir));
            }

            Ok(Config {
                middleware_port,
                input_dir,
                output_dir,
                username: "stress_test_user".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 8080,
                middleware_ip: "127.0.0.1".to_string(),
                server_urls: vec![
                    "http://127.0.0.1:8000".to_string(),
                ],
            })
        }

        pub fn print(&self) {
            println!("========================================");
            println!("Cloud P2P Stress Test Client");
            println!("========================================");
            println!("Middleware Port:      {}", self.middleware_port);
            println!("Input Directory:      {}", self.input_dir);
            println!("Output Directory:     {}", self.output_dir);
            println!("Middleware Address:   {}:{}", self.middleware_ip, self.middleware_port);
            println!("Server URLs:          {} configured", self.server_urls.len());
            println!("========================================\n");
        }
    }
}

// =======================================
// Main Entry Point
// =======================================

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let config = match config::Config::from_args(args) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("\nExample:");
            eprintln!("  stress_test_client 9000 ./test_images ./encrypted_output");
            std::process::exit(1);
        }
    };

    let input_dir = Path::new(&config.input_dir);
    let output_dir = Path::new(&config.output_dir);

    let image_files = match filesystem::get_image_files(input_dir) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = filesystem::create_output_directory(output_dir) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    config.print();
    println!("Images Found:         {}\n", image_files.len());

    let middleware = ClientMiddleware::new(
        &config.middleware_ip,
        config.middleware_port,
        config.server_urls.clone()
    );

    let middleware_handle = thread::spawn(move || {
        if let Err(e) = middleware.start() {
            eprintln!("[Middleware] Error: {}", e);
        }
    });

    thread::sleep(Duration::from_millis(200));

    let middleware_addr = format!("{}:{}", config.middleware_ip, config.middleware_port);
    let client = Client::new(
        &config.username,
        &config.client_ip,
        config.client_port,
        &middleware_addr
    );

    let runner = stress_test::StressTestRunner::new(client, output_dir.to_path_buf());
    runner.run(image_files);

    println!("[StressTest] Shutting down...");
    println!("[StressTest] Note: Middleware is still running (background thread)");
    println!("[StressTest] Press Ctrl+C to fully exit\n");

    let _ = middleware_handle.join();
}