use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserspaceShaper {
    pub bandwidth_bytes_per_sec: Option<u64>,
    pub latency: Duration,
}

impl UserspaceShaper {
    pub fn disabled() -> Self {
        Self {
            bandwidth_bytes_per_sec: None,
            latency: Duration::ZERO,
        }
    }

    pub fn delay_for(&self, bytes: usize) -> Duration {
        let bandwidth_delay = self.bandwidth_bytes_per_sec.map_or(Duration::ZERO, |rate| {
            if rate == 0 {
                Duration::ZERO
            } else {
                Duration::from_secs_f64(bytes as f64 / rate as f64)
            }
        });
        self.latency + bandwidth_delay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_delay() {
        let shaper = UserspaceShaper {
            bandwidth_bytes_per_sec: Some(100),
            latency: Duration::from_millis(5),
        };
        assert!(shaper.delay_for(100) >= Duration::from_millis(1005));
    }
}
