//! The documented HCS reply shapes. Raw HCS documents and parser diagnostics
//! never cross the helper boundary.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

pub const MAX_REPLY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Schema {
    pub major: u32,
    pub minor: u32,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct Capabilities {
    pub schemas: Vec<Schema>,
    pub nested_virtualization: bool,
}

#[cfg(any(windows, test))]
impl Capabilities {
    pub(crate) fn parse(basic: &str, processors: &str) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Basic {
            supported_schema_versions: Vec<Schema>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct BasicReply {
            properties: Vec<Basic>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct ProcessorInfo {
            processor_features: Vec<String>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct ProcessorResponse {
            response: ProcessorInfo,
            error: Option<serde::de::IgnoredAny>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct ProcessorResponses {
            processor_capabilities: ProcessorResponse,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct ProcessorReply {
            property_responses: ProcessorResponses,
        }
        let basic: BasicReply = decode(basic)?;
        let processors: ProcessorReply = decode(processors)?;
        let [basic] = basic.properties.as_slice() else {
            return Err(Error("invalid_hcs_capabilities"));
        };
        let processors = processors.property_responses.processor_capabilities;
        if basic.supported_schema_versions.is_empty()
            || basic.supported_schema_versions.len() > 64
            || basic
                .supported_schema_versions
                .iter()
                .any(|version| version.major == 0)
            || processors.error.is_some()
            || processors.response.processor_features.len() > 1024
            || processors
                .response
                .processor_features
                .iter()
                .any(|feature| feature.len() > 128)
        {
            return Err(Error("invalid_hcs_capabilities"));
        }
        Ok(Self {
            schemas: basic.supported_schema_versions.clone(),
            nested_virtualization: processors
                .response
                .processor_features
                .iter()
                .any(|feature| feature == "NestedVirt"),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum State {
    Created,
    Running,
    Paused,
    Stopped,
    SavedAsTemplate,
    Unknown,
}

#[cfg(any(windows, test))]
#[derive(Debug)]
pub(crate) struct Properties {
    pub state: State,
    pub runtime_id: Option<u128>,
}

#[cfg(any(windows, test))]
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SystemProperties {
    id: String,
    system_type: String,
    owner: String,
    #[serde(default, deserialize_with = "present_runtime_id")]
    runtime_id: Option<String>,
    state: State,
}

#[cfg(any(windows, test))]
impl Properties {
    pub(crate) fn parse(document: &str, expected_id: &str, expected_owner: &str) -> Result<Self> {
        Self::validate(decode(document)?, expected_id, expected_owner)
    }

    pub(crate) fn inventory(
        document: &str,
        expected_id: &str,
        expected_owner: &str,
    ) -> Result<Option<Self>> {
        validate_owner(expected_id, expected_owner)?;
        let mut entries: Vec<SystemProperties> = decode(document)?;
        if entries.len() > 1 {
            return Err(Error("invalid_hcs_inventory"));
        }
        entries
            .pop()
            .map(|entry| Self::validate(entry, expected_id, expected_owner))
            .transpose()
    }

    fn validate(reply: SystemProperties, expected_id: &str, expected_owner: &str) -> Result<Self> {
        validate_owner(expected_id, expected_owner)?;
        if reply.id != expected_id
            || reply.system_type != "VirtualMachine"
            || reply.owner != expected_owner
        {
            return Err(Error("invalid_hcs_properties"));
        }
        Ok(Self {
            state: reply.state,
            runtime_id: reply
                .runtime_id
                .as_deref()
                .map(guid)
                .transpose()
                .map_err(|_| Error("invalid_hcs_runtime_id"))?,
        })
    }
}

/// HCS SystemQuery uses Ids, not Owners: an existing foreign generation must
/// be detected rather than hidden by an owner-filtered inventory.
#[cfg(any(windows, test))]
pub(crate) fn system_query(id: &str) -> Result<String> {
    canonical_id(id)?;
    #[derive(Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct Query<'a> {
        ids: [&'a str; 1],
    }
    serde_json::to_string(&Query { ids: [id] }).map_err(|_| Error("invalid_hcs_query"))
}

#[cfg(any(windows, test))]
pub(crate) fn absent(document: &str, expected_id: &str) -> Result<bool> {
    canonical_id(expected_id)?;
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Present {
        id: String,
    }
    let entries: Vec<Present> = decode(document)?;
    if entries.len() > 1 || entries.iter().any(|entry| entry.id != expected_id) {
        return Err(Error("invalid_hcs_inventory"));
    }
    Ok(entries.is_empty())
}

pub(crate) fn owner(id: &str, generation: &str) -> Result<String> {
    let id = canonical_id(id)?;
    if !identifier(generation) {
        return Err(Error("invalid_runtime_generation"));
    }
    Ok(format!("Oblivion.{id:032x}.{generation}"))
}

pub(crate) fn validate_owner(id: &str, value: &str) -> Result<()> {
    let prefix = format!("Oblivion.{:032x}.", canonical_id(id)?);
    if !value.strip_prefix(&prefix).is_some_and(identifier) {
        return Err(Error("invalid_hcs_owner"));
    }
    Ok(())
}

#[cfg(any(windows, test))]
pub(crate) fn creation(document: &str, id: &str, expected_owner: &str) -> Result<()> {
    validate_owner(id, expected_owner)?;
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Creation {
        owner: String,
        should_terminate_on_last_handle_closed: bool,
    }
    let created: Creation = decode(document)?;
    if created.owner != expected_owner || !created.should_terminate_on_last_handle_closed {
        return Err(Error("invalid_hcs_owner"));
    }
    Ok(())
}

fn canonical_id(id: &str) -> Result<u128> {
    let parsed = guid(id)?;
    if format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        parsed >> 96,
        (parsed >> 80) & 0xffff,
        (parsed >> 64) & 0xffff,
        (parsed >> 48) & 0xffff,
        parsed & 0xffffffffffff,
    ) != id
    {
        return Err(Error("invalid_hcs_id"));
    }
    Ok(parsed)
}

fn identifier(value: &str) -> bool {
    value.len() == 32
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(any(windows, test))]
fn present_runtime_id<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    // HCS may omit RuntimeId after exit; an explicitly malformed value is not
    // an absent identifier and must not be usable as a Hyper-V socket address.
    String::deserialize(deserializer).map(Some)
}

#[cfg(any(windows, test))]
fn decode<T: serde::de::DeserializeOwned>(document: &str) -> Result<T> {
    if document.len() > MAX_REPLY_BYTES {
        return Err(Error("hcs_reply_too_large"));
    }
    serde_json::from_str(document).map_err(|_| Error("invalid_hcs_reply"))
}

pub(crate) fn guid(value: &str) -> Result<u128> {
    // HCS uses the Windows GUID string form, with optional surrounding braces.
    let value = value
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(value);
    if value.len() != 36 {
        return Err(Error("invalid_hyperv_guid"));
    }
    let mut result = 0_u128;
    for (position, byte) in value.bytes().enumerate() {
        if [8, 13, 18, 23].contains(&position) {
            if byte != b'-' {
                return Err(Error("invalid_hyperv_guid"));
            }
            continue;
        }
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(Error("invalid_hyperv_guid")),
        };
        result = (result << 4) | u128::from(digit);
    }
    if result == 0 {
        return Err(Error("invalid_hyperv_guid"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{
        Capabilities, Error, MAX_REPLY_BYTES, Properties, Schema, State, absent, creation, owner,
        system_query, validate_owner,
    };
    const ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const OWNER: &str =
        "Oblivion.00112233445566778899aabbccddeeff.0123456789abcdef0123456789abcdef";
    const BASIC: &str = r#"{"Properties":[{"SupportedSchemaVersions":[{"Major":2,"Minor":11}]}]}"#;
    const PROCESSORS: &str = r#"{"PropertyResponses":{"ProcessorCapabilities":{"Response":{"ProcessorFeatures":["Sse3","NestedVirt"]}}}}"#;

    #[test]
    fn per_start_owner_requires_the_exact_canonical_runtime_and_generation() {
        let generation = "0123456789abcdef0123456789abcdef";
        assert_eq!(owner(ID, generation).unwrap(), OWNER);
        validate_owner(ID, OWNER).unwrap();
        for invalid in [
            "Oblivion".to_owned(),
            OWNER.to_ascii_lowercase(),
            OWNER.replace(generation, &"0".repeat(32)),
            format!("{OWNER}.extra"),
            OWNER.replace("00112233445566778899aabbccddeeff", &"1".repeat(32)),
        ] {
            assert_eq!(
                validate_owner(ID, &invalid),
                Err(Error("invalid_hcs_owner"))
            );
        }
        for invalid in [
            "",
            "0",
            "00000000000000000000000000000000",
            "A123456789abcdef0123456789abcdef",
        ] {
            assert_eq!(owner(ID, invalid), Err(Error("invalid_runtime_generation")));
        }
        assert!(owner(&format!("{{{ID}}}"), generation).is_err());
        assert!(owner(&ID.to_uppercase(), generation).is_err());
        assert_eq!(system_query(ID).unwrap(), format!(r#"{{"Ids":["{ID}"]}}"#));
        let configuration = format!(
            r#"{{"Owner":"{OWNER}","ShouldTerminateOnLastHandleClosed":true,"VirtualMachine":{{}}}}"#
        );
        creation(&configuration, ID, OWNER).unwrap();
        assert!(creation(&configuration.replace("true", "false"), ID, OWNER).is_err());
        assert!(creation(&configuration.replace(OWNER, "foreign"), ID, OWNER).is_err());
    }

    #[test]
    fn inventory_never_hides_a_collision_or_accepts_foreign_generation_as_stopped() {
        assert!(absent("[]", ID).unwrap());
        assert!(Properties::inventory("[]", ID, OWNER).unwrap().is_none());
        let present = format!(
            r#"[{{"Id":"{ID}","Owner":"{OWNER}","SystemType":"VirtualMachine","State":"Stopped"}}]"#
        );
        assert!(!absent(&present, ID).unwrap());
        assert_eq!(
            Properties::inventory(&present, ID, OWNER)
                .unwrap()
                .unwrap()
                .state,
            State::Stopped
        );
        for invalid in [
            present.replace(OWNER, "foreign-generation"),
            present.replace("VirtualMachine", "Container"),
            present.replace(ID, "11223344-5566-7788-99aa-bbccddeeff00"),
            format!(
                "[{},{}]",
                &present[1..present.len() - 1],
                &present[1..present.len() - 1]
            ),
            "null".into(),
        ] {
            assert!(Properties::inventory(&invalid, ID, OWNER).is_err());
        }
        for invalid in [
            "{}".to_owned(),
            present.replace(ID, "11223344-5566-7788-99aa-bbccddeeff00"),
            format!(
                "[{},{}]",
                &present[1..present.len() - 1],
                &present[1..present.len() - 1]
            ),
        ] {
            assert!(absent(&invalid, ID).is_err());
        }
        // Presence rejects create even if unrelated fields cannot authorize
        // recovery; absence never relies on parsing an owner filter.
        assert!(!absent(&present.replace(OWNER, "foreign-generation"), ID).unwrap());
    }

    #[test]
    fn official_basic_and_processor_queries_preserve_explicit_nested_capability() {
        let capabilities = Capabilities::parse(BASIC, PROCESSORS).unwrap();
        assert_eq!(
            capabilities.schemas,
            [Schema {
                major: 2,
                minor: 11
            }]
        );
        assert!(capabilities.nested_virtualization);
        let without = PROCESSORS.replace(",\"NestedVirt\"", "");
        assert!(
            !Capabilities::parse(BASIC, &without)
                .unwrap()
                .nested_virtualization
        );
        let error = PROCESSORS.replace(
            "\"Response\":",
            "\"Error\":{\"Error\":-1,\"ErrorMessage\":\"secret-canary\"},\"Response\":",
        );
        assert_eq!(
            Capabilities::parse(BASIC, &error).unwrap_err(),
            Error("invalid_hcs_capabilities")
        );
        for invalid in [
            "{}",
            r#"{"Properties":[]}"#,
            r#"{"Properties":[{"SupportedSchemaVersions":[]}]}"#,
        ] {
            assert!(Capabilities::parse(invalid, PROCESSORS).is_err());
        }
    }

    #[test]
    fn state_and_runtime_guid_come_from_the_owned_machine_properties() {
        let document = r#"{"Id":"00112233-4455-6677-8899-aabbccddeeff","Owner":"Oblivion.00112233445566778899aabbccddeeff.0123456789abcdef0123456789abcdef","SystemType":"VirtualMachine","State":"Running","RuntimeId":"{00112233-4455-6677-8899-aabbccddeeff}","Stopped":false}"#;
        let properties = Properties::parse(document, ID, OWNER).unwrap();
        assert_eq!(properties.state, State::Running);
        assert_eq!(
            properties.runtime_id,
            Some(0x00112233445566778899aabbccddeeff)
        );
        let unknown = Properties::parse(
            &document
                .replace("Running", "Unknown")
                .replace("false", "true"),
            ID,
            OWNER,
        )
        .unwrap();
        assert_eq!(unknown.state, State::Unknown);
        let stopped = Properties::parse(
            r#"{"Id":"00112233-4455-6677-8899-aabbccddeeff","Owner":"Oblivion.00112233445566778899aabbccddeeff.0123456789abcdef0123456789abcdef","SystemType":"VirtualMachine","State":"Stopped"}"#,
            ID, OWNER,
        )
        .unwrap();
        assert_eq!(stopped.state, State::Stopped);
        assert!(stopped.runtime_id.is_none());
        for invalid in [
            document.replace(ID, "11223344-5566-7788-99aa-bbccddeeff00"),
            document.replace("VirtualMachine", "Container"),
            document.replace(
                "00112233-4455-6677-8899-aabbccddeeff",
                "00000000-0000-0000-0000-000000000000",
            ),
        ] {
            assert!(Properties::parse(&invalid, ID, OWNER).is_err());
        }
    }

    #[test]
    fn reply_bounds_and_malformed_values_only_return_static_errors() {
        let oversized = " ".repeat(MAX_REPLY_BYTES + 1);
        assert_eq!(
            Capabilities::parse(&oversized, PROCESSORS).unwrap_err(),
            Error("hcs_reply_too_large")
        );
        let document = r#"{"Id":"00112233-4455-6677-8899-aabbccddeeff","Owner":"Oblivion.00112233445566778899aabbccddeeff.0123456789abcdef0123456789abcdef","SystemType":"VirtualMachine","State":"secret-canary","RuntimeId":"00112233-4455-6677-8899-aabbccddeeff"}"#;
        let error = match Properties::parse(document, ID, OWNER) {
            Ok(_) => panic!("accepted unknown state"),
            Err(error) => error,
        };
        assert_eq!(error, Error("invalid_hcs_reply"));
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert!(std::error::Error::source(&error).is_none());
        assert!(Properties::parse(
            r#"{"Id":"00112233-4455-6677-8899-aabbccddeeff","Owner":"Oblivion.00112233445566778899aabbccddeeff.0123456789abcdef0123456789abcdef","SystemType":"VirtualMachine","State":"Stopped","RuntimeId":null}"#,
            ID, OWNER,
        )
        .is_err());
    }
}
