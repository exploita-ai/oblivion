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
pub(crate) struct Properties {
    pub state: State,
    pub runtime_id: Option<u128>,
}

#[cfg(any(windows, test))]
impl Properties {
    pub(crate) fn parse(document: &str, expected_id: &str) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Reply {
            id: String,
            system_type: String,
            #[serde(default, deserialize_with = "present_runtime_id")]
            runtime_id: Option<String>,
            state: State,
        }
        let reply: Reply = decode(document)?;
        if reply.id != expected_id || reply.system_type != "VirtualMachine" {
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
    use super::{Capabilities, Error, Properties, Schema, State, MAX_REPLY_BYTES};
    const BASIC: &str = r#"{"Properties":[{"SupportedSchemaVersions":[{"Major":2,"Minor":11}]}]}"#;
    const PROCESSORS: &str = r#"{"PropertyResponses":{"ProcessorCapabilities":{"Response":{"ProcessorFeatures":["Sse3","NestedVirt"]}}}}"#;

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
        let document = r#"{"Id":"owned","SystemType":"VirtualMachine","State":"Running","RuntimeId":"{00112233-4455-6677-8899-aabbccddeeff}","Stopped":false}"#;
        let properties = Properties::parse(document, "owned").unwrap();
        assert_eq!(properties.state, State::Running);
        assert_eq!(
            properties.runtime_id,
            Some(0x00112233445566778899aabbccddeeff)
        );
        let unknown = Properties::parse(
            &document
                .replace("Running", "Unknown")
                .replace("false", "true"),
            "owned",
        )
        .unwrap();
        assert_eq!(unknown.state, State::Unknown);
        let stopped = Properties::parse(
            r#"{"Id":"owned","SystemType":"VirtualMachine","State":"Stopped"}"#,
            "owned",
        )
        .unwrap();
        assert_eq!(stopped.state, State::Stopped);
        assert!(stopped.runtime_id.is_none());
        for invalid in [
            document.replace("owned", "other"),
            document.replace("VirtualMachine", "Container"),
            document.replace(
                "00112233-4455-6677-8899-aabbccddeeff",
                "00000000-0000-0000-0000-000000000000",
            ),
        ] {
            assert!(Properties::parse(&invalid, "owned").is_err());
        }
    }

    #[test]
    fn reply_bounds_and_malformed_values_only_return_static_errors() {
        let oversized = " ".repeat(MAX_REPLY_BYTES + 1);
        assert_eq!(
            Capabilities::parse(&oversized, PROCESSORS).unwrap_err(),
            Error("hcs_reply_too_large")
        );
        let document = r#"{"Id":"owned","SystemType":"VirtualMachine","State":"secret-canary","RuntimeId":"00112233-4455-6677-8899-aabbccddeeff"}"#;
        let error = match Properties::parse(document, "owned") {
            Ok(_) => panic!("accepted unknown state"),
            Err(error) => error,
        };
        assert_eq!(error, Error("invalid_hcs_reply"));
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert!(std::error::Error::source(&error).is_none());
        assert!(Properties::parse(
            r#"{"Id":"owned","SystemType":"VirtualMachine","State":"Stopped","RuntimeId":null}"#,
            "owned",
        )
        .is_err());
    }
}
