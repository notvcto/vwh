//! `.vwh.note` header parsing.
//!
//! A note MAY begin with a block of `key: value` header lines terminated by a
//! blank line, followed by the freeform body:
//!
//! ```text
//! registry: https://notvc.to/vwh-registry
//!
//! Routine lab capture — see ticket #1234.
//! ```
//!
//! The whole file (headers + body) is what gets BLAKE3-hashed into the
//! artifact, so headers are as tamper-evident as the note itself. Notes with
//! no header block (the pre-4.0 freeform style) parse as empty headers + full
//! body, so old notes keep verifying unchanged.

use std::collections::HashMap;

/// Split a note into (headers, body). Headers are lowercased keys.
///
/// A leading block is treated as headers only if it is terminated by a blank
/// line AND every line in it is a well-formed `key: value` pair. Otherwise the
/// entire content is the body and headers are empty.
pub fn parse_note(bytes: &[u8]) -> (HashMap<String, String>, String) {
    let text = String::from_utf8_lossy(bytes);
    let text = text.as_ref();

    if let Some(idx) = text.find("\n\n") {
        let head = &text[..idx];
        let body = &text[idx + 2..];

        if !head.is_empty() {
            let mut headers = HashMap::new();
            let mut all_headers = true;
            for line in head.lines() {
                match line.split_once(':') {
                    Some((k, v)) if is_header_key(k) => {
                        headers.insert(k.trim().to_lowercase(), v.trim().to_string());
                    }
                    _ => {
                        all_headers = false;
                        break;
                    }
                }
            }
            if all_headers && !headers.is_empty() {
                return (headers, body.to_string());
            }
        }
    }

    (HashMap::new(), text.to_string())
}

fn is_header_key(k: &str) -> bool {
    let k = k.trim();
    !k.is_empty()
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Compose a note with a `registry:` header in front of the body.
pub fn note_with_registry(registry: &str, body: &str) -> String {
    format!("registry: {}\n\n{}", registry.trim(), body.trim())
}

/// The registry URL to stamp into a newly created note: `VWH_REGISTRY_URL`
/// if set, otherwise the built-in default.
pub fn registry_for_new_note() -> String {
    std::env::var("VWH_REGISTRY_URL")
        .unwrap_or_else(|_| crate::inspect::DEFAULT_REGISTRY_URL.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeform_note_is_all_body() {
        let (h, b) = parse_note(b"just a plain note\nsecond line");
        assert!(h.is_empty());
        assert_eq!(b, "just a plain note\nsecond line");
    }

    #[test]
    fn registry_header_is_parsed_and_stripped() {
        let note = note_with_registry("https://ex.test/reg", "the body");
        let (h, b) = parse_note(note.as_bytes());
        assert_eq!(h.get("registry").map(String::as_str), Some("https://ex.test/reg"));
        assert_eq!(b, "the body");
    }

    #[test]
    fn colon_body_without_blank_line_is_body() {
        // No blank line ⇒ not a header block.
        let (h, b) = parse_note(b"registry: not actually a header");
        assert!(h.is_empty());
        assert_eq!(b, "registry: not actually a header");
    }
}
