use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rename {
    pub id: String,
    pub title: String,
}

pub fn validate(title: &str) -> Result<(), &'static str> {
    if title.trim().is_empty()
        || title != title.trim()
        || title.len() > 256
        || title.chars().count() > 80
        || title.chars().any(|c| c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
    {
        return Err("invalid_session_title");
    }
    Ok(())
}
