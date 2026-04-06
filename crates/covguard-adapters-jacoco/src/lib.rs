//! JaCoCo XML coverage file parser for covguard.
//!
//! This crate provides parsing of JaCoCo XML format coverage files,
//! producing a normalized coverage map that can be used by the domain layer.

use std::collections::BTreeMap;

use quick_xml::Reader;
use quick_xml::events::Event;
use thiserror::Error;

use covguard_paths::normalize_coverage_path_with_strip;
use covguard_ports::{CoverageMap, CoverageProvider};

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur while parsing JaCoCo XML files.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JacocoError {
    /// Invalid XML format.
    #[error("Invalid XML: {0}")]
    InvalidXml(String),

    /// Invalid JaCoCo format - missing required elements.
    #[error("Invalid JaCoCo format: {0}")]
    InvalidFormat(String),

    /// Invalid attribute value.
    #[error("Invalid attribute value: {0}")]
    InvalidAttribute(String),
}

// ============================================================================
// JaCoCo Parsing
// ============================================================================

/// Parse a JaCoCo XML format string into a coverage map.
pub fn parse_jacoco(text: &str) -> Result<CoverageMap, JacocoError> {
    parse_jacoco_with_strip(text, &[])
}

/// Parse a JaCoCo XML format string into a coverage map with optional prefix stripping.
pub fn parse_jacoco_with_strip(
    text: &str,
    strip_prefixes: &[String],
) -> Result<CoverageMap, JacocoError> {
    let mut coverage_map: CoverageMap = BTreeMap::new();
    let mut reader = Reader::from_str(text);

    // State machine for parsing
    let mut current_package: Option<String> = None;
    let mut current_sourcefile: Option<String> = None;
    let mut current_lines: BTreeMap<u32, u32> = BTreeMap::new();

    // Buffer for event parsing
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let decoder = reader.decoder();
                match e.local_name().as_ref() {
                    b"package" => {
                        // Extract package name attribute
                        for attr_result in e.attributes() {
                            let attr = attr_result.map_err(|e| {
                                JacocoError::InvalidXml(format!("Failed to parse attribute: {}", e))
                            })?;
                            if attr.key.as_ref() == b"name" {
                                let value = attr.decode_and_unescape_value(decoder);
                                let value = value.map_err(|e| {
                                    JacocoError::InvalidXml(format!(
                                        "Failed to decode attribute value: {}",
                                        e
                                    ))
                                })?;
                                current_package = Some(value.to_string());
                                break;
                            }
                        }
                    }
                    b"sourcefile" => {
                        // Save previous sourcefile if any
                        if let (Some(pkg), Some(sf)) =
                            (current_package.as_ref(), current_sourcefile.as_ref())
                        {
                            let path = build_path(pkg, sf);
                            let normalized =
                                normalize_coverage_path_with_strip(&path, strip_prefixes);
                            merge_file_coverage(&mut coverage_map, &normalized, &current_lines);
                            current_lines.clear();
                        }

                        // Extract sourcefile name attribute
                        for attr_result in e.attributes() {
                            let attr = attr_result.map_err(|e| {
                                JacocoError::InvalidXml(format!("Failed to parse attribute: {}", e))
                            })?;
                            if attr.key.as_ref() == b"name" {
                                let value = attr.decode_and_unescape_value(decoder);
                                let value = value.map_err(|e| {
                                    JacocoError::InvalidXml(format!(
                                        "Failed to decode attribute value: {}",
                                        e
                                    ))
                                })?;
                                current_sourcefile = Some(value.to_string());
                                break;
                            }
                        }
                    }
                    b"line" => {
                        // Extract line number (nr) and covered instructions (ci)
                        let mut line_nr: Option<u32> = None;
                        let mut covered_instructions: Option<u32> = None;

                        for attr_result in e.attributes() {
                            let attr = attr_result.map_err(|e| {
                                JacocoError::InvalidXml(format!("Failed to parse attribute: {}", e))
                            })?;

                            match attr.key.as_ref() {
                                b"nr" => {
                                    let value = attr.decode_and_unescape_value(decoder);
                                    let value = value.map_err(|e| {
                                        JacocoError::InvalidXml(format!(
                                            "Failed to decode nr attribute: {}",
                                            e
                                        ))
                                    })?;
                                    line_nr = Some(value.parse::<u32>().map_err(|_| {
                                        JacocoError::InvalidAttribute(format!(
                                            "Invalid line number: '{}'",
                                            value
                                        ))
                                    })?);
                                }
                                b"ci" => {
                                    let value = attr.decode_and_unescape_value(decoder);
                                    let value = value.map_err(|e| {
                                        JacocoError::InvalidXml(format!(
                                            "Failed to decode ci attribute: {}",
                                            e
                                        ))
                                    })?;
                                    covered_instructions =
                                        Some(value.parse::<u32>().map_err(|_| {
                                            JacocoError::InvalidAttribute(format!(
                                                "Invalid covered instructions: '{}'",
                                                value
                                            ))
                                        })?);
                                }
                                _ => {}
                            }
                        }

                        // Record line coverage if we have both attributes
                        if let (Some(nr), Some(ci)) = (line_nr, covered_instructions) {
                            current_lines.insert(nr, ci);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                match e.local_name().as_ref() {
                    b"sourcefile" => {
                        // Save the sourcefile coverage
                        if let (Some(pkg), Some(sf)) =
                            (current_package.as_ref(), current_sourcefile.take())
                        {
                            let path = build_path(pkg, &sf);
                            let normalized =
                                normalize_coverage_path_with_strip(&path, strip_prefixes);
                            merge_file_coverage(&mut coverage_map, &normalized, &current_lines);
                            current_lines.clear();
                        }
                    }
                    b"package" => {
                        current_package = None;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(JacocoError::InvalidXml(format!(
                    "XML parsing error at position {}: {:?}",
                    reader.error_position(),
                    e
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(coverage_map)
}

/// Build a full path from package and sourcefile names.
fn build_path(package: &str, sourcefile: &str) -> String {
    if package.is_empty() {
        sourcefile.to_string()
    } else {
        format!("{}/{}", package, sourcefile)
    }
}

/// Merge file coverage into the coverage map.
fn merge_file_coverage(coverage_map: &mut CoverageMap, file: &str, lines: &BTreeMap<u32, u32>) {
    if lines.is_empty() {
        return;
    }
    let entry = coverage_map.entry(file.to_string()).or_default();
    for (line, hits) in lines {
        let existing = entry.entry(*line).or_insert(*hits);
        if *hits > *existing {
            *existing = *hits;
        }
    }
}

/// Check if the content appears to be a JaCoCo XML report.
pub fn is_jacoco_format(text: &str) -> bool {
    let trimmed = text.trim();
    if !trimmed.starts_with("<?xml") && !trimmed.starts_with("<report") {
        return false;
    }
    if let Some(report_start) = trimmed.find("<report") {
        let before_report = &trimmed[..report_start];
        let cleaned: String = before_report
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if cleaned.is_empty()
            || cleaned.starts_with("<?xml")
                && cleaned.trim_end_matches('?').trim_end().ends_with(">")
        {
            return true;
        }
    }
    if trimmed.contains("<report")
        && (trimmed.contains("<package") || trimmed.contains("<sourcefile"))
    {
        return true;
    }
    false
}

/// JaCoCo coverage provider implementation.
pub struct JacocoCoverageProvider;

impl CoverageProvider for JacocoCoverageProvider {
    fn parse_coverage(
        &self,
        text: &str,
        format: covguard_types::CoverageFormat,
        strip_prefixes: &[String],
    ) -> Result<CoverageMap, String> {
        if format != covguard_types::CoverageFormat::Jacoco
            && format != covguard_types::CoverageFormat::Auto
        {
            return Err(format!(
                "JacocoCoverageProvider only supports Jacoco format, got {:?}",
                format
            ));
        }
        if format == covguard_types::CoverageFormat::Auto && !is_jacoco_format(text) {
            return Err("Auto-detection failed for Jacoco format".to_string());
        }
        parse_jacoco_with_strip(text, strip_prefixes).map_err(|e| e.to_string())
    }

    fn merge_coverage(&self, maps: Vec<CoverageMap>) -> CoverageMap {
        let mut merged: CoverageMap = BTreeMap::new();
        for map in maps {
            for (file, lines) in map {
                let entry = merged.entry(file).or_default();
                for (line, hits) in lines {
                    let current = entry.entry(line).or_insert(0);
                    *current = (*current).max(hits);
                }
            }
        }
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jacoco_minimal() {
        let jacoco = r#"<?xml version="1.0" encoding="UTF-8"?>
<report name="Test">
  <package name="com/example">
    <sourcefile name="Foo.java">
      <line nr="5" ci="3" mi="0" mb="0" cb="0"/>
    </sourcefile>
  </package>
</report>"#;

        let coverage = parse_jacoco(jacoco).unwrap();
        assert!(coverage.contains_key("com/example/Foo.java"));
        assert_eq!(coverage["com/example/Foo.java"].get(&5), Some(&3));
    }

    #[test]
    fn test_is_jacoco_format_valid() {
        let jacoco = r#"<?xml version="1.0" encoding="UTF-8"?>
<report name="Test">
  <package name="com/example">
    <sourcefile name="Foo.java">
      <line nr="5" ci="3" mi="0"/>
    </sourcefile>
  </package>
</report>"#;
        assert!(is_jacoco_format(jacoco));
    }
}
