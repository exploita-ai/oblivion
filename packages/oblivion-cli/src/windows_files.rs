//! Guest-owned Files metadata for the native Windows frontend. Local Windows
//! publication remains a separate filesystem endpoint, never a stream fallback.
use crate::controller::Result;
use crate::files::Backend;
use crate::windows::Runtime;
use oblivion_transfer::native_files::{Action, Request, Status, TransfersPage, TransfersQuery};
use oblivion_wire::idle::Opening;
use oblivion_wire::slot::Slot;

impl Backend for Runtime {
    fn transfers(
        &mut self,
        opening: &Opening<Slot>,
        query: &TransfersQuery,
        destination: Option<&str>,
    ) -> Result<TransfersPage> {
        if destination.is_some() {
            return Err("windows_filesystem_endpoint_not_implemented".into());
        }
        self.file_query(
            opening,
            &Request::Transfers {
                safe_id: query.safe_id.clone(),
                opening: query.opening.clone(),
                after: query.after.clone(),
                limit: query.limit,
            },
        )
    }

    fn manage(
        &mut self,
        opening: &Opening<Slot>,
        operation: &str,
        action: Action,
        destination: Option<&str>,
    ) -> Result<Status> {
        if destination.is_some() {
            return Err("windows_filesystem_endpoint_not_implemented".into());
        }
        let request = match action {
            Action::Status => Request::Status {
                id: operation.into(),
                safe_id: opening.safe_id.clone(),
                opening: opening.nonce.clone(),
            },
            Action::Recover => Request::Recover {
                id: operation.into(),
                safe_id: opening.safe_id.clone(),
                opening: opening.nonce.clone(),
            },
            Action::Discard => Request::Discard {
                id: operation.into(),
                safe_id: opening.safe_id.clone(),
                opening: opening.nonce.clone(),
            },
        };
        self.file_query(opening, &request)
    }
}
