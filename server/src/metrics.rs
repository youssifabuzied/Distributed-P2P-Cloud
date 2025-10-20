// =======================================
// metrics.rs - Dynamic Priority Calculation
// Cloud P2P Controlled Image Sharing Project
// =======================================
//
// Calculates server priority based on:
// - CPU load (1-minute average)
// - Available memory
// - Historical response time
//

use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{Duration, Instant};

// =======================================
// Configuration
// =======================================

/// Weights for priority calculation (must sum to 1.0)
#[derive(Clone, Debug)]
pub struct PriorityWeights {
    pub cpu_weight: f32,      // Default: 0.4 (40%)
    pub memory_weight: f32,   // Default: 0.3 (30%)
    pub response_weight: f32, // Default: 0.3 (30%)
}

impl Default for PriorityWeights {
    fn default() -> Self {
        PriorityWeights {
            cpu_weight: 0.4,
            memory_weight: 0.3,
            response_weight: 0.3,
        }
    }
}

/// Configuration for priority calculation
#[derive(Clone, Debug)]
pub struct PriorityConfig {
    pub weights: PriorityWeights,
    pub max_response_time_ms: f32, // Maximum expected response time (default: 5000ms)
    pub enable_logging: bool,      // Enable detailed logging
}

impl Default for PriorityConfig {
    fn default() -> Self {
        PriorityConfig {
            weights: PriorityWeights::default(),
            max_response_time_ms: 5000.0,
            enable_logging: true,
        }
    }
}

// =======================================
// System Metrics
// =======================================

/// System metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_load_1min: f32,       // 1-minute CPU load average (0.0 - cores)
    pub cpu_cores: usize,         // Number of CPU cores
    pub memory_total_mb: u64,     // Total memory in MB
    pub memory_available_mb: u64, // Available memory in MB
    pub memory_used_mb: u64,      // Used memory in MB
    pub timestamp: u64,           // Unix timestamp
}

/// Normalized scores (0-100 range)
#[derive(Debug, Clone)]
pub struct MetricScores {
    pub cpu_score: f32,      // 100 = no load, 0 = fully loaded
    pub memory_score: f32,   // 100 = all free, 0 = all used
    pub response_score: f32, // 100 = instant, 0 = timeout
}

// =======================================
// Priority Calculator
// =======================================

pub struct PriorityCalculator {
    config: PriorityConfig,
    response_history: Vec<Duration>, // Last N response times
    max_history_size: usize,
}

impl PriorityCalculator {
    /// Create new priority calculator
    pub fn new(config: PriorityConfig) -> Self {
        PriorityCalculator {
            config,
            response_history: Vec::new(),
            max_history_size: 10, // Keep last 10 response times
        }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(PriorityConfig::default())
    }

    /// Calculate dynamic priority based on current system state
    pub fn calculate_priority(&self) -> Result<f32, String> {
        // Gather system metrics
        let metrics = self.gather_system_metrics()?;

        // Calculate individual scores
        let scores = self.calculate_scores(&metrics);

        // Calculate weighted priority
        let priority = self.calculate_weighted_priority(&scores);

        if self.config.enable_logging {
            self.log_priority_calculation(&metrics, &scores, priority);
        }

        Ok(priority)
    }

    /// Gather current system metrics
    fn gather_system_metrics(&self) -> Result<SystemMetrics, String> {
        let cpu_load = self.get_cpu_load_1min()?;
        let cpu_cores = self.get_cpu_cores()?;
        let (memory_total, memory_available) = self.get_memory_info()?;

        let memory_used = memory_total.saturating_sub(memory_available);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(SystemMetrics {
            cpu_load_1min: cpu_load,
            cpu_cores,
            memory_total_mb: memory_total,
            memory_available_mb: memory_available,
            memory_used_mb: memory_used,
            timestamp,
        })
    }

    /// Calculate normalized scores (0-100) from raw metrics
    fn calculate_scores(&self, metrics: &SystemMetrics) -> MetricScores {
        // CPU Score: 100 = no load, 0 = overloaded
        // Normalize by number of cores (load of 1.0 per core = 100% utilization)
        let cpu_utilization = (metrics.cpu_load_1min / metrics.cpu_cores as f32).min(1.0);
        let cpu_score = 100.0 * (1.0 - cpu_utilization);

        // Memory Score: 100 = all free, 0 = all used
        let memory_free_ratio = metrics.memory_available_mb as f32 / metrics.memory_total_mb as f32;
        let memory_score = 100.0 * memory_free_ratio;

        // Response Score: 100 = fast, 0 = slow
        let avg_response_ms = self.get_average_response_time_ms();
        let response_ratio = (avg_response_ms / self.config.max_response_time_ms).min(1.0);
        let response_score = 100.0 * (1.0 - response_ratio);

        MetricScores {
            cpu_score,
            memory_score,
            response_score,
        }
    }

    /// Calculate weighted priority from scores
    fn calculate_weighted_priority(&self, scores: &MetricScores) -> f32 {
        let w = &self.config.weights;

        let priority = (w.cpu_weight * scores.cpu_score)
            + (w.memory_weight * scores.memory_score)
            + (w.response_weight * scores.response_score);

        // Clamp to valid range [0.0, 100.0]
        priority.max(0.0).min(100.0)
    }

    /// Record a response time for future calculations
    pub fn record_response_time(&mut self, duration: Duration) {
        self.response_history.push(duration);

        // Keep only recent history
        if self.response_history.len() > self.max_history_size {
            self.response_history.remove(0);
        }
    }

    /// Get average response time in milliseconds
    fn get_average_response_time_ms(&self) -> f32 {
        if self.response_history.is_empty() {
            return 100.0; // Default to 100ms if no history
        }

        let sum: Duration = self.response_history.iter().sum();
        let avg = sum / self.response_history.len() as u32;
        avg.as_millis() as f32
    }

    // =======================================
    // System Metric Collection
    // =======================================

    /// Get 1-minute CPU load average (Linux/Unix)
    fn get_cpu_load_1min(&self) -> Result<f32, String> {
        #[cfg(target_os = "linux")]
        {
            let loadavg = fs::read_to_string("/proc/loadavg")
                .map_err(|e| format!("Failed to read /proc/loadavg: {}", e))?;

            let parts: Vec<&str> = loadavg.split_whitespace().collect();
            if parts.is_empty() {
                return Err("Invalid /proc/loadavg format".to_string());
            }

            parts[0]
                .parse::<f32>()
                .map_err(|e| format!("Failed to parse load average: {}", e))
        }

        #[cfg(target_os = "macos")]
        {
            // macOS: use sysctl
            use std::process::Command;
            let output = Command::new("sysctl")
                .arg("-n")
                .arg("vm.loadavg")
                .output()
                .map_err(|e| format!("Failed to run sysctl: {}", e))?;

            let loadavg = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = loadavg.trim().split_whitespace().collect();

            // Format: { 0.50 0.45 0.40 }
            if parts.len() < 2 {
                return Err("Invalid sysctl output".to_string());
            }

            parts[1]
                .parse::<f32>()
                .map_err(|e| format!("Failed to parse load: {}", e))
        }

        #[cfg(target_os = "windows")]
        {
            // Windows: fallback to default (no native load average)
            Ok(0.5) // Conservative default
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err("Unsupported operating system".to_string())
        }
    }

    /// Get number of CPU cores
    fn get_cpu_cores(&self) -> Result<usize, String> {
        Ok(num_cpus::get())
    }

    /// Get memory information (total, available) in MB
    fn get_memory_info(&self) -> Result<(u64, u64), String> {
        #[cfg(target_os = "linux")]
        {
            let meminfo = fs::read_to_string("/proc/meminfo")
                .map_err(|e| format!("Failed to read /proc/meminfo: {}", e))?;

            let mut total_kb = 0u64;
            let mut available_kb = 0u64;

            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    total_kb = Self::parse_meminfo_line(line)?;
                } else if line.starts_with("MemAvailable:") {
                    available_kb = Self::parse_meminfo_line(line)?;
                }
            }

            if total_kb == 0 {
                return Err("Failed to parse MemTotal".to_string());
            }

            // Convert KB to MB
            Ok((total_kb / 1024, available_kb / 1024))
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;

            // Get total memory
            let total_output = Command::new("sysctl")
                .arg("-n")
                .arg("hw.memsize")
                .output()
                .map_err(|e| format!("Failed to get memory: {}", e))?;

            let total_bytes = String::from_utf8_lossy(&total_output.stdout)
                .trim()
                .parse::<u64>()
                .map_err(|e| format!("Failed to parse memory: {}", e))?;

            // Get free memory (approximate)
            let free_output = Command::new("vm_stat")
                .output()
                .map_err(|e| format!("Failed to run vm_stat: {}", e))?;

            let vm_stat = String::from_utf8_lossy(&free_output.stdout);
            let mut free_pages = 0u64;

            for line in vm_stat.lines() {
                if line.contains("Pages free:") {
                    if let Some(num_str) = line.split(':').nth(1) {
                        free_pages = num_str.trim().trim_end_matches('.').parse().unwrap_or(0);
                        break;
                    }
                }
            }

            let page_size = 4096u64; // macOS page size
            let free_bytes = free_pages * page_size;

            Ok((total_bytes / 1024 / 1024, free_bytes / 1024 / 1024))
        }

        #[cfg(target_os = "windows")]
        {
            // Windows: would need winapi crate
            // Fallback to conservative defaults
            Ok((8192, 4096)) // 8GB total, 4GB free
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err("Unsupported operating system".to_string())
        }
    }

    /// Parse a line from /proc/meminfo (Linux)
    #[cfg(target_os = "linux")]
    fn parse_meminfo_line(line: &str) -> Result<u64, String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(format!("Invalid meminfo line: {}", line));
        }

        parts[1]
            .parse::<u64>()
            .map_err(|e| format!("Failed to parse memory value: {}", e))
    }

    /// Log priority calculation details
    fn log_priority_calculation(
        &self,
        metrics: &SystemMetrics,
        scores: &MetricScores,
        priority: f32,
    ) {
        println!("\n========================================");
        println!("Dynamic Priority Calculation");
        println!("========================================");
        println!("[Metrics]");
        println!(
            "  CPU Load (1min): {:.2} / {} cores",
            metrics.cpu_load_1min, metrics.cpu_cores
        );
        println!(
            "  Memory Used: {} MB / {} MB ({:.1}%)",
            metrics.memory_used_mb,
            metrics.memory_total_mb,
            (metrics.memory_used_mb as f32 / metrics.memory_total_mb as f32) * 100.0
        );
        println!(
            "  Avg Response: {:.2}ms",
            self.get_average_response_time_ms()
        );

        println!("\n[Scores] (0-100, higher is better)");
        println!("  CPU Score:      {:.2}/100", scores.cpu_score);
        println!("  Memory Score:   {:.2}/100", scores.memory_score);
        println!("  Response Score: {:.2}/100", scores.response_score);

        println!("\n[Weights]");
        println!(
            "  CPU Weight:      {:.0}%",
            self.config.weights.cpu_weight * 100.0
        );
        println!(
            "  Memory Weight:   {:.0}%",
            self.config.weights.memory_weight * 100.0
        );
        println!(
            "  Response Weight: {:.0}%",
            self.config.weights.response_weight * 100.0
        );

        println!("\n[Final Priority]: {:.2}/100", priority);
        println!("========================================\n");
    }
}

// =======================================
// Helper: num_cpus replacement (if not available)
// =======================================

#[cfg(not(feature = "use_num_cpus"))]
mod num_cpus {
    pub fn get() -> usize {
        #[cfg(target_os = "linux")]
        {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        }

        #[cfg(not(target_os = "linux"))]
        {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        }
    }
}

// =======================================
// Tests
// =======================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_calculation() {
        let calculator = PriorityCalculator::default();
        let priority = calculator.calculate_priority();

        assert!(priority.is_ok());
        let p = priority.unwrap();
        assert!(p >= 0.0 && p <= 100.0, "Priority out of range: {}", p);
    }

    #[test]
    fn test_score_normalization() {
        let calculator = PriorityCalculator::default();
        let metrics = SystemMetrics {
            cpu_load_1min: 0.5,
            cpu_cores: 4,
            memory_total_mb: 8192,
            memory_available_mb: 4096,
            memory_used_mb: 4096,
            timestamp: 0,
        };

        let scores = calculator.calculate_scores(&metrics);

        assert!(scores.cpu_score >= 0.0 && scores.cpu_score <= 100.0);
        assert!(scores.memory_score >= 0.0 && scores.memory_score <= 100.0);
        assert!(scores.response_score >= 0.0 && scores.response_score <= 100.0);
    }
}
