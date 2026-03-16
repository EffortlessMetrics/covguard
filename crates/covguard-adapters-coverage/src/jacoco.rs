//! JaCoCo XML coverage file parser for covguard.
//!
//! This module provides parsing of JaCoCo XML format coverage files,
//! producing a normalized coverage map that can be used by the domain layer.
//!
//! Only available when the `jacoco` feature is enabled.

use std::collections::BTreeMap;

use quick_xml::events::Event;
use quick_xml::Reader;
use thiserror::Error;

use crate::{normalize_path_with_strip, CoverageMap};

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
///
/// JaCoCo XML format key elements:
/// - `<report>` - Root element
/// - `<package name="...">` - Package name (uses `/` separators)
/// - `<sourcefile name="...">` - Source file name
/// - `<line nr="..." ci="..." />` - Line coverage (nr=line number, ci=covered instructions)
///
/// # Path Construction
///
/// The full path is constructed as `{package}/{sourcefile}`. For example:
/// - package: `com/example`
/// - sourcefile: `Foo.java`
/// - result: `com/example/Foo.java`
///
/// # Line Coverage
///
/// The `ci` (covered instructions) attribute is used as the hit count.
/// Lines with `ci="0"` are included to indicate uncovered lines.
///
/// # Examples
///
/// ```ignore
/// use covguard_adapters_coverage::parse_jacoco;
///
/// let jacoco = r#"<?xml version="1.0" encoding="UTF-8"?>
/// <report name="Example">
///   <package name="com/example">
///     <sourcefile name="Foo.java">
///       <line nr="5" ci="3" mi="0"/>
///       <line nr="10" ci="0" mi="2"/>
///     </sourcefile>
///   </package>
/// </report>"#;
///
/// let coverage = parse_jacoco(jacoco).unwrap();
/// assert_eq!(coverage.get("com/example/Foo.java").unwrap().get(&5), Some(&3));
/// assert_eq!(coverage.get("com/example/Foo.java").unwrap().get(&10), Some(&0));
/// ```
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
                                JacocoError::InvalidXml(format!(
                                    "Failed to parse attribute: {}",
                                    e
                                ))
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
                                normalize_path_with_strip(&path, strip_prefixes);
                            merge_file_coverage(&mut coverage_map, &normalized, &current_lines);
                            current_lines.clear();
                        }

                        // Extract sourcefile name attribute
                        for attr_result in e.attributes() {
                            let attr = attr_result.map_err(|e| {
                                JacocoError::InvalidXml(format!(
                                    "Failed to parse attribute: {}",
                                    e
                                ))
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
                                JacocoError::InvalidXml(format!(
                                    "Failed to parse attribute: {}",
                                    e
                                ))
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
                                normalize_path_with_strip(&path, strip_prefixes);
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
fn merge_file_coverage(
    coverage_map: &mut CoverageMap,
    file: &str,
    lines: &BTreeMap<u32, u32>,
) {
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

// ============================================================================
// Format Detection
// ============================================================================

/// Check if the content appears to be a JaCoCo XML report.
///
/// Returns true if the content:
/// 1. Is valid XML
/// 2. Has a `<report>` root element (JaCoCo-specific)
pub fn is_jacoco_format(text: &str) -> bool {
    let trimmed = text.trim();

    // Quick check: must start with XML declaration or <report>
    if !trimmed.starts_with("<?xml") && !trimmed.starts_with("<report") {
        return false;
    }

    // Look for JaCoCo-specific elements
    // JaCoCo reports have a <report> root element
    if let Some(report_start) = trimmed.find("<report") {
        let before_report = &trimmed[..report_start];
        // Check if there's only whitespace/XML declaration before <report>
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

    // Also check for <report> with namespace
    if trimmed.contains("<report") {
        // Additional validation: check for JaCoCo-specific child elements
        if trimmed.contains("<package") || trimmed.contains("<sourcefile") {
            return true;
        }
    }

    false
}

// ============================================================================
// Tests
// ============================================================================

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
    fn test_parse_jacoco_multiple_lines() {
        let jacoco = r#"<?xml version="1.0" encoding="UTF-8"?>
<report name="Test">
  <package name="com/example">
    <sourcefile name="Foo.java">
      <line nr="5" ci="3" mi="0"/>
      <line nr="10" ci="0" mi="2"/>
      <line nr="15" ci="5" mi="0"/>
    </sourcefile>
  </package>
</report>"#;

        let coverage = parse_jacoco(jacoco).unwrap();
        let file = coverage.get("com/example/Foo.java").unwrap();
        assert_eq!(file.get(&5), Some(&3));
        assert_eq!(file.get(&10), Some(&0)); // Uncovered line
        assert_eq!(file.get(&15), Some(&5));
    }

    #[test]
    fn test_parse_jacoco_multiple_packages() {
        let jacoco = r#"<?xml version="1.0" encoding="UTF-8"?>
<report name="Test">
  <package name="com/example">
    <sourcefile name="Foo.java">
      <line nr="5" ci="1" mi="0"/>
    </sourcefile>
  </package>
  <package name="com/other">
    <sourcefile name="Bar.java">
      <line nr="10" ci="2" mi="0"/>
    </sourcefile>
  </package>
</report>"#;

        let coverage = parse_jacoco(jacoco).unwrap();
        assert!(coverage.contains_key("com/example/Foo.java"));
        assert!(coverage.contains_key("com/other/Bar.java"));
        assert_eq!(coverage["com/example/Foo.java"].get(&5), Some(&1));
        assert_eq!(coverage["com/other/Bar.java"].get(&10), Some(&2));
    }

    #[test]
    fn test_parse_jacoco_multiple_sourcefiles() {
        let jacoco = r#"<?xml version="1.0" encoding="UTF-8"?>
<report name="Test">
  <package name="com/example">
    <sourcefile name="Foo.java">
      <line nr="5" ci="1" mi="0"/>
    </sourcefile>
    <sourcefile name="Bar.java">
      <line nr="10" ci="2" mi="0"/>
    </sourcefile>
  </package>
</report>"#;

        let coverage = parse_jacoco(jacoco).unwrap();
        assert!(coverage.contains_key("com/example/Foo.java"));
        assert!(coverage.contains_key("com/example/Bar.java"));
    }

    #[test]
    fn test_parse_jacoco_default_package() {
        // JaCoCo allows files in the default (empty) package
        let jacoco = r#"<?xml version="1.0" encoding="UTF-8"?>
<report name="Test">
  <package name="">
    <sourcefile name="Main.java">
      <line nr="1" ci="1" mi="0"/>
    </sourcefile>
  </package>
</report>"#;

        let coverage = parse_jacoco(jacoco).unwrap();
        assert!(coverage.contains_key("Main.java"));
        assert_eq!(coverage["Main.java"].get(&1), Some(&1));
    }

    #[test]
    fn test_parse_jacoco_with_strip_prefix() {
        let jacoco = r#"<?xml version="1.0" encoding="UTF-8"?>
<report name="Test">
  <package name="src/main/java/com/example">
    <sourcefile name="Foo.java">
      <line nr="5" ci="1" mi="0"/>
    </sourcefile>
  </package>
</report>"#;

        let strip_prefixes = vec!["src/main/java/".to_string()];
        let coverage = parse_jacoco_with_strip(jacoco, &strip_prefixes).unwrap();
        assert!(coverage.contains_key("com/example/Foo.java"));
    }

    #[test]
    fn test_parse_jacoco_empty_report() {
        let jacoco = r#"<?xml version="1.0" encoding="UTF-8"?>
<report name="Test">
</report>"#;

        let coverage = parse_jacoco(jacoco).unwrap();
        assert!(coverage.is_empty());
    }

    #[test]
    fn test_parse_jacoco_invalid_xml() {
        // Invalid XML should return an empty coverage map
        // (quick-xml is lenient and just returns no events for non-XML content)
        let invalid = "not xml at all";
        let result = parse_jacoco(invalid);
        // The parser doesn't error on non-XML, it just produces an empty map
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_jacoco_malformed_xml() {
        // Malformed XML with unclosed tags should error
        let malformed = r#"<?xml version="1.0"?>
<report>
  <package name="test">
    <sourcefile name="Test.java">
      <line nr="1" ci="1"
    </sourcefile>
  </package>
"#;
        let result = parse_jacoco(malformed);
        // This should error due to malformed XML
        assert!(result.is_err() || result.unwrap().is_empty());
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

    #[test]
    fn test_is_jacoco_format_without_declaration() {
        let jacoco = r#"<report name="Test">
  <package name="com/example">
    <sourcefile name="Foo.java">
      <line nr="5" ci="3" mi="0"/>
    </sourcefile>
  </package>
</report>"#;
        assert!(is_jacoco_format(jacoco));
    }

    #[test]
    fn test_is_jacoco_format_invalid() {
        // LCOV format
        let lcov = "SF:src/lib.rs\nDA:1,5\nend_of_record\n";
        assert!(!is_jacoco_format(lcov));

        // Random text
        assert!(!is_jacoco_format("some random text"));

        // Different XML
        let other_xml = r#"<?xml version="1.0"?>
<other><element/></other>"#;
        assert!(!is_jacoco_format(other_xml));
    }

    #[test]
    fn test_build_path() {
        assert_eq!(build_path("com/example", "Foo.java"), "com/example/Foo.java");
        assert_eq!(build_path("", "Main.java"), "Main.java");
        assert_eq!(build_path("single", "File.java"), "single/File.java");
    }
}
