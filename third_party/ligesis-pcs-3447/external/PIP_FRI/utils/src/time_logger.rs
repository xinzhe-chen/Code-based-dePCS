use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref LOGGER: Mutex<TimeLogger> = Mutex::new(TimeLogger::new());
}

pub struct TimeLogger {
    file_path: Option<String>,
    times: Vec<f64>,
}

impl TimeLogger {
    pub fn new() -> Self {
        Self {
            file_path: None,
            times: vec![],
        }
    }

    pub fn init(&mut self, file_path: String) {
        self.file_path = Some(file_path);
    }

    pub fn record(&mut self, t: f64) {
        self.times.push(t);
    }

    pub fn flush(&mut self) {
        if self.times.is_empty() || self.file_path.is_none() {
            return;
        }

        let line = self
            .times
            .iter()
            .map(|t| format!("{:.6}", t))
            .collect::<Vec<_>>()
            .join(",");

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.file_path.as_ref().unwrap())
            .expect("Failed to open log file");

        writeln!(file, "{}", line).expect("Failed to write time log");

        self.times.clear();
    }
}
