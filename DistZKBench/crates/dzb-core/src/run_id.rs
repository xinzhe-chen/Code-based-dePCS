use std::time::{SystemTime, UNIX_EPOCH};

pub fn new_run_id(prefix: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    let pid = std::process::id();
    format!("{prefix}-{millis}-{pid}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_id_has_prefix() {
        assert!(new_run_id("toy").starts_with("toy-"));
    }
}
