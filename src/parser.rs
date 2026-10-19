use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetKind {
    Domain,
    Ip,
}

#[derive(Clone, Debug)]
pub struct Target {
    pub host: String,
    pub kind: TargetKind,
}

impl Target {
    fn dedup_key(&self) -> String {
        let tag = match self.kind {
            TargetKind::Domain => "d",
            TargetKind::Ip => "i",
        };
        format!("{}:{}", tag, self.host.to_lowercase())
    }
}

pub struct ParseOutcome {
    pub valid: Vec<Target>,
    pub invalid: Vec<String>,
}

pub fn parse_input(input: &str) -> ParseOutcome {
    let mut valid: Vec<Target> = Vec::new();
    let mut invalid: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for token in split_tokens(input) {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        match parse_single(trimmed) {
            Some(target) => {
                if seen.insert(target.dedup_key()) {
                    valid.push(target);
                }
            }
            None => invalid.push(trimmed.to_string()),
        }
    }

    ParseOutcome { valid, invalid }
}

fn split_tokens(input: &str) -> Vec<String> {
    input
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(|s| s.to_string())
        .collect()
}

pub fn parse_single(token: &str) -> Option<Target> {
    let host = extract_host(token)?;
    if host.is_empty() {
        return None;
    }
    if is_ipv4(&host) {
        return Some(Target {
            host,
            kind: TargetKind::Ip,
        });
    }
    if is_valid_domain(&host) {
        return Some(Target {
            host: host.to_lowercase(),
            kind: TargetKind::Domain,
        });
    }
    None
}

fn extract_host(token: &str) -> Option<String> {
    let mut slice = token.trim();

    if let Some(idx) = slice.find("://") {
        slice = &slice[idx + 3..];
    }
    if let Some(idx) = slice.find('@') {
        slice = &slice[idx + 1..];
    }

    let end = slice.find(['/', '?', '#']).unwrap_or(slice.len());
    slice = &slice[..end];

    let host = if let Some(stripped) = slice.strip_prefix('[') {
        &stripped[..stripped.find(']')?]
    } else if let Some(colon) = slice.rfind(':') {
        let port = &slice[colon + 1..];
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            &slice[..colon]
        } else {
            slice
        }
    } else {
        slice
    };

    Some(host.trim().trim_end_matches('.').to_string())
}

fn is_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for part in parts {
        if part.is_empty() || part.len() > 3 || !part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        match part.parse::<u32>() {
            Ok(value) if value <= 255 => {}
            _ => return false,
        }
    }
    true
}

fn is_valid_domain(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.starts_with('.') || host.ends_with('.') || host.starts_with('-') {
        return false;
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    host.chars().any(|c| c.is_ascii_alphabetic())
}
