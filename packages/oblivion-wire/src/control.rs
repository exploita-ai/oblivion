use serde::de::IntoDeserializer;
use serde::{Deserialize, Serialize};

// These are the existing controller and desktop relay limits.
pub const HEADER_LIMIT: usize = 1024;
pub const RESPONSE_LIMIT: usize = 1024 * 1024;
pub const NATIVE_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    FamilyPasswordPreview,
    FamilyPasswordChange,
    FamilyPasswordStatus,
    FamilyPasswordRecover,
    BackupExportBegin,
    BackupImportBegin,
    BackupAttach,
    BackupImportFinish,
    BackupStatus,
    BackupCancel,
    BackupDiscard,
    InitGeneral,
    SafeAccess,
    OpenDocuments,
    OpenChildDocuments,
    OpenDocumentsEphemeral,
    StartAgent,
    ChildTaskStatus,
    ChildTaskReview,
    ChildTaskStart,
    ChildTaskRetry,
    ChildTaskCancel,
    PinSafe,
    AgentAttach,
    FileAttach,
    AgentRelease,
    ShareAttach,
    ShareRelease,
    ShareExportCancel,
    ShareExportBegin,
    ShareExportLease,
    ShareExportEnd,
    ShareExportSourceOpen,
    ShareImportBegin,
    ShareImportOpen,
    ShareImportAttach,
    ShareImportFinish,
    ShareImportCommit,
    ShareImportAbort,
    ShareImportDiscard,
    ShareImportStatus,
    ShutdownRuntime,
    ShutdownIdle,
    Browse,
    Diagnostics,
    DiscardGeneralPending,
    DiscardSessionPending,
    Unlock,
    UnlockReadOnly,
    EnterRam,
    Create,
    RenameSession,
    SessionStorage,
    Close,
    CloseIdle,
    ForceClose,
    Lock,
    Status,
    Activity,
    IdleSettings,
    Debug,
    Egress,
    ProxyProfiles,
    NetworkPolicy,
    Transfers,
    Onion,
}

impl Operation {
    pub fn parse(value: &str) -> Result<Self, serde::de::value::Error> {
        Self::deserialize(value.into_deserializer())
    }
}

/// A secret is a separate bounded byte sequence after this JSON header. It can
/// never become a JSON field, command-line argument or diagnostic via this DTO.
/// The receiver owns validation of its slot type and operation authorization.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request<S> {
    pub expected_session: Option<String>,
    pub operation: Operation,
    pub secret_len: u32,
    pub session: Option<String>,
    #[serde(default)]
    pub slot: S,
}

/// Only the desktop relay has a version field; the local controller does not.
/// This outbound wrapper cannot accidentally change the local request schema.
#[derive(Serialize)]
pub struct NativeRequest<'a, S> {
    #[serde(flatten)]
    request: &'a Request<S>,
    version: u8,
}

impl<'a, S> NativeRequest<'a, S> {
    pub fn new(request: &'a Request<S>) -> Self {
        Self {
            request,
            version: NATIVE_VERSION,
        }
    }
}

/// Resource leases and passed descriptors remain local server state. S permits
/// the server to serialize borrowed fields without cloning response contents.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Response<S = String> {
    pub ok: bool,
    pub output: S,
    pub error: Option<S>,
}
