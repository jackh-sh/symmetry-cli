use anyhow::{Context, Result};

/// Parse dotenv-format bytes into key/value pairs (supports quoting,
/// comments, and blank lines via dotenvy).
pub fn parse(bytes: &[u8]) -> Result<Vec<(String, String)>> {
    let mut vars = Vec::new();
    for item in dotenvy::from_read_iter(std::io::Cursor::new(bytes)) {
        vars.push(item.context("failed to parse env file")?);
    }
    Ok(vars)
}

/// Does this line assign `key` (optionally with an `export ` prefix)?
fn is_line_for(line: &str, key: &str) -> bool {
    let trimmed = line.trim_start();
    let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    match trimmed.strip_prefix(key) {
        Some(rest) => rest.trim_start().starts_with('='),
        None => false,
    }
}

/// Quote a value only when the dotenv format needs it.
fn format_value(value: &str) -> String {
    let plain = !value.is_empty()
        && !value
            .chars()
            .any(|c| c.is_whitespace() || "#\"'\\$`".contains(c));
    if plain {
        return value.to_string();
    }
    if !value.contains('\'') && !value.contains('\n') {
        // Single quotes are fully literal in dotenv.
        return format!("'{value}'");
    }
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
            .replace('\n', "\\n")
    )
}

/// Set or add `key` in dotenv-format text, editing lines in place so
/// comments, ordering, and unrelated entries survive. Edits the last
/// occurrence since that's the one dotenv semantics make effective.
pub fn set_var(text: &str, key: &str, value: &str) -> String {
    let assignment = format!("{key}={}", format_value(value));
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    match lines.iter().rposition(|line| is_line_for(line, key)) {
        Some(i) => {
            let exported = lines[i].trim_start().starts_with("export ");
            lines[i] = if exported {
                format!("export {assignment}")
            } else {
                assignment
            };
        }
        None => lines.push(assignment),
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Remove every assignment of `key`. Returns the new text and whether
/// anything was removed.
pub fn unset_var(text: &str, key: &str) -> (String, bool) {
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !is_line_for(line, key))
        .collect();
    let found = lines.len() != text.lines().count();
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    (out, found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_of(text: &str, key: &str) -> Option<String> {
        parse(text.as_bytes())
            .unwrap()
            .into_iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    #[test]
    fn parses_comments_quotes_and_blanks() {
        let vars = parse(b"# comment\nA=1\n\nB=\"two words\"\nC='single'\n").unwrap();
        assert_eq!(
            vars,
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "two words".into()),
                ("C".into(), "single".into()),
            ]
        );
    }

    #[test]
    fn set_updates_existing_key_and_keeps_comments() {
        let text = "# db config\nDB_URL=old\nOTHER=1\n";
        let updated = set_var(text, "DB_URL", "new");
        assert_eq!(updated, "# db config\nDB_URL=new\nOTHER=1\n");
    }

    #[test]
    fn set_appends_missing_key() {
        let updated = set_var("A=1\n", "B", "2");
        assert_eq!(updated, "A=1\nB=2\n");
        assert_eq!(set_var("", "A", "1"), "A=1\n");
    }

    #[test]
    fn set_preserves_export_prefix_and_edits_last_duplicate() {
        let updated = set_var("export A=1\n", "A", "2");
        assert_eq!(updated, "export A=2\n");

        let updated = set_var("A=1\nA=2\n", "A", "3");
        assert_eq!(updated, "A=1\nA=3\n");
    }

    #[test]
    fn set_does_not_touch_prefix_matches() {
        let updated = set_var("ABC=1\n", "A", "2");
        assert_eq!(updated, "ABC=1\nA=2\n");
    }

    #[test]
    fn set_values_roundtrip_through_the_parser() {
        for value in [
            "simple",
            "two words",
            "pa$$word",
            "quote\"inside",
            "single'quote",
            "back\\slash",
            "trailing space ",
            "# not a comment",
            "",
        ] {
            let text = set_var("", "KEY", value);
            assert_eq!(
                value_of(&text, "KEY").as_deref(),
                Some(value),
                "value {value:?} did not roundtrip through {text:?}"
            );
        }
    }

    #[test]
    fn unset_removes_all_occurrences() {
        let (out, found) = unset_var("A=1\nB=2\nexport A=3\n", "A");
        assert_eq!(out, "B=2\n");
        assert!(found);

        let (out, found) = unset_var("B=2\n", "A");
        assert_eq!(out, "B=2\n");
        assert!(!found);
    }
}
