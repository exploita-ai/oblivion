//! Platform authorities for the shared Share workflow. Wire messages, source
//! review, import mapping and publication decisions stay in the common engine.
use crate::controller::{Call, Result};
use crate::run::Runtime;
use oblivion_transfer::copy_protocol::Transport;
use oblivion_wire::idle::Opening;
use std::io;

pub const REVIEW_LINE_LIMIT: usize = 64;

pub trait Attachment {
    type Stream: Transport;
    fn stream(&mut self) -> &mut Self::Stream;
    fn client_id(&self) -> &str;
    fn close(&mut self) -> io::Result<()>;
}

pub trait Lease {
    fn check(&mut self) -> io::Result<()>;
    fn close(&mut self) -> io::Result<()>;
}

pub trait Native: Runtime {
    type Attachment: Attachment;
    type ExportLease: Lease;

    /// Read one public review command from the controlling terminal. EOF or
    /// cancellation returns None, while Enter alone returns an empty line.
    fn review_share(&mut self) -> Result<Option<String>>;
    fn lease_share_export(&mut self, export: &str) -> Result<Self::ExportLease>;
    fn attach_share_source(
        &mut self,
        opening: &Opening<Self::Slot>,
        lease: &mut Self::ExportLease,
    ) -> Result<Self::Attachment>;
    fn attach_share_import(&mut self, opening: &Opening<Self::Slot>) -> Result<Self::Attachment>;
    /// Cancellation revokes data I/O, but cleanup still addresses the exact
    /// authenticated controller and captured slot/client/opening.
    fn cleanup(&mut self, call: Call<'_, Self::Slot>) -> Result<String>;
}
