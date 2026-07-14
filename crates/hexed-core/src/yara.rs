//! YARA rule scanning via the pure-Rust `yara-x` engine.

#[derive(Clone, Debug)]
pub struct YaraMatch {
    pub rule: String,
    /// (offset, length) of each matched pattern occurrence.
    pub locations: Vec<(usize, usize)>,
}

/// Compile `source` and scan `data`. Returns matches, or a compile/scan error
/// string suitable for showing to the user.
pub fn yara_scan(source: &str, data: &[u8]) -> Result<Vec<YaraMatch>, String> {
    let rules = yara_x::compile(source).map_err(|e| e.to_string())?;
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner.scan(data).map_err(|e| format!("scan error: {e:?}"))?;
    let mut out = Vec::new();
    for r in results.matching_rules() {
        let mut locations = Vec::new();
        for p in r.patterns() {
            for m in p.matches() {
                let range = m.range();
                locations.push((range.start, range.end - range.start));
            }
        }
        out.push(YaraMatch {
            rule: r.identifier().to_string(),
            locations,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_and_matches() {
        let rule = r#"rule demo { strings: $a = "malware" condition: $a }"#;
        let hits = yara_scan(rule, b"this is malware sample").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "demo");
        assert_eq!(hits[0].locations, vec![(8, 7)]);
    }

    #[test]
    fn no_match_and_bad_rule() {
        assert!(yara_scan(r#"rule x { strings: $a = "zzz" condition: $a }"#, b"abc")
            .unwrap()
            .is_empty());
        assert!(yara_scan("not a valid rule", b"abc").is_err());
    }
}
