use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    pub version: u8,
    pub completed: bool,
    pub keyboard: String,
    #[serde(default)]
    pub variant: String,
    pub timezone: String,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            version: 1,
            completed: false,
            keyboard: "us".into(),
            variant: String::new(),
            timezone: "UTC".into(),
        }
    }
}

impl Preferences {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1 {
            return Err("invalid_settings_version");
        }
        if self.keyboard.is_empty()
            || self.keyboard.len() > 64
            || self.variant.len() > 64
            || !self
                .keyboard
                .bytes()
                .chain(self.variant.bytes())
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err("invalid_keyboard");
        }
        if self.timezone.is_empty()
            || self.timezone.len() > 128
            || self.timezone.starts_with('/')
            || self
                .timezone
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !self
                .timezone
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_+-".contains(&byte))
        {
            return Err("invalid_timezone");
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
pub struct Choice {
    pub value: String,
    pub label: String,
}

#[derive(Deserialize, Serialize)]
pub struct Keyboard {
    pub value: String,
    pub label: String,
    pub variants: Vec<Choice>,
}

#[derive(Deserialize, Serialize)]
pub struct Catalog {
    pub keyboards: Vec<Keyboard>,
    pub timezones: Vec<String>,
}

impl Catalog {
    pub fn validate(&self, preferences: &Preferences) -> Result<(), &'static str> {
        preferences.validate()?;
        if !self.keyboards.iter().any(|layout| {
            layout.value == preferences.keyboard
                && layout
                    .variants
                    .iter()
                    .any(|variant| variant.value == preferences.variant)
        }) {
            return Err("invalid_keyboard");
        }
        if !self.timezones.contains(&preferences.timezone) {
            return Err("invalid_timezone");
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Apply { preferences: Preferences },
    Save { preferences: Preferences },
}

#[derive(Deserialize, Serialize)]
pub struct Status {
    pub current: Preferences,
    pub saved: Option<Preferences>,
}
