#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitError(pub String);

impl std::fmt::Display for UnitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for UnitError {}

pub fn parse_byte_size(value: &str) -> Result<u64, UnitError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(UnitError("empty byte size".to_owned()));
    }
    let split = trimmed
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (number, suffix) = trimmed.split_at(split);
    let base = number
        .parse::<u64>()
        .map_err(|_| UnitError(format!("invalid byte size number '{number}'")))?;
    let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "kib" => 1024,
        "mib" => 1024 * 1024,
        "gib" => 1024 * 1024 * 1024,
        "kb" => 1000,
        "mb" => 1000 * 1000,
        "gb" => 1000 * 1000 * 1000,
        other => return Err(UnitError(format!("unsupported byte suffix '{other}'"))),
    };
    base.checked_mul(multiplier)
        .ok_or_else(|| UnitError("byte size overflow".to_owned()))
}

pub fn parse_duration_millis(value: &str) -> Result<u64, UnitError> {
    let trimmed = value.trim();
    let split = trimmed
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (number, suffix) = trimmed.split_at(split);
    let base = number
        .parse::<u64>()
        .map_err(|_| UnitError(format!("invalid duration number '{number}'")))?;
    match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "ms" => Ok(base),
        "s" => base
            .checked_mul(1000)
            .ok_or_else(|| UnitError("duration overflow".to_owned())),
        other => Err(UnitError(format!("unsupported duration suffix '{other}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_byte_sizes() {
        assert_eq!(parse_byte_size("16MiB"), Ok(16 * 1024 * 1024));
        assert_eq!(parse_byte_size("2GB"), Ok(2_000_000_000));
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration_millis("50ms"), Ok(50));
        assert_eq!(parse_duration_millis("2s"), Ok(2000));
    }
}
