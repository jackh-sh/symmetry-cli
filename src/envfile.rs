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

#[cfg(test)]
mod tests {
    use super::*;

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
}
