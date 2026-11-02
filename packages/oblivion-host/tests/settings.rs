use oblivion_host::settings::{Command, Preferences};

#[test]
fn existing_profiles_default_to_standard_variant_and_catalog_controls_values() {
    let mut old: Preferences = serde_json::from_str(
        r#"{"version":1,"completed":true,"keyboard":"it","timezone":"Europe/Rome"}"#,
    )
    .unwrap();
    assert_eq!(old.variant, "");
    assert_eq!(old.web_access, "strict");
    assert_eq!(old.session_idle_minutes, 15);
    assert_eq!(old.host_idle_minutes, 30);
    let catalog: oblivion_host::settings::Catalog = serde_json::from_str(r#"{"keyboards":[{"value":"it","label":"Italian","variants":[{"value":"","label":"Default"},{"value":"mac","label":"Macintosh"}]}],"timezones":["UTC","Europe/Rome"]}"#).unwrap();
    catalog.validate(&old).unwrap();
    old.variant = "mac".into();
    catalog.validate(&old).unwrap();
    old.variant = "invented".into();
    assert!(catalog.validate(&old).is_err());
    old.variant.clear();
    old.timezone = "Invented/City".into();
    assert!(catalog.validate(&old).is_err());
}

#[test]
fn setup_roundtrips_without_accepting_paths_or_extra_commands() {
    let preferences = Preferences {
        keyboard: "it".into(),
        timezone: "Europe/Rome".into(),
        completed: true,
        ..Preferences::default()
    };
    assert!(preferences.validate().is_ok());
    let command = serde_json::to_vec(&Command::Save { preferences }).unwrap();
    let Command::Save { preferences } = serde_json::from_slice(&command).unwrap() else {
        panic!()
    };
    assert!(preferences.completed);
    assert_eq!(preferences.keyboard, "it");
    assert_eq!(preferences.timezone, "Europe/Rome");
    for timezone in [
        "/etc/shadow",
        "../UTC",
        "Europe/../UTC",
        "Europe//Rome",
        "UTC\n",
        "",
        "Europe/Rome;id",
    ] {
        assert!(
            Preferences {
                timezone: timezone.into(),
                ..Preferences::default()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        Preferences {
            keyboard: "../../us".into(),
            ..Preferences::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Preferences {
            web_access: "unknown".into(),
            ..Preferences::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Preferences {
            session_idle_minutes: 60,
            host_idle_minutes: 30,
            ..Preferences::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Preferences {
            session_idle_minutes: 1,
            ..Preferences::default()
        }
        .validate()
        .is_err()
    );
    assert!(serde_json::from_str::<Command>(r#"{"action":"apply","preferences":{"version":1,"completed":false,"keyboard":"us","timezone":"UTC","command":"id"}}"#).is_err());
}

#[test]
fn new_profiles_start_open_and_global_access_has_three_modes() {
    assert_eq!(Preferences::default().web_access, "open");
    for mode in ["open", "strict", "offline"] {
        let command: Command = serde_json::from_value(
            serde_json::json!({"action": "access", "mode": mode, "save": true}),
        )
        .unwrap();
        assert!(matches!(command, Command::Access { save: true, .. }));
    }
    assert!(
        serde_json::from_value::<Command>(
            serde_json::json!({"action": "access", "mode": "direct", "save": false})
        )
        .is_err()
    );
}
