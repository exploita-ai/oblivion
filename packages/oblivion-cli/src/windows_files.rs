//! Guest and explicitly selected native receiver metadata use the same Files
//! outcomes. Inspecting a local destination never mounts the Safe filesystem.
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
        if let Some(destination) = destination {
            let target = std::path::absolute(destination)?;
            return Ok(oblivion_transfer::stream::operations::inventory(
                &target.join(".oblivion-transfers"),
                &target,
                query,
            )?);
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
        if let Some(destination) = destination {
            let target = std::path::absolute(destination)?;
            return Ok(oblivion_transfer::stream::operations::manage(
                &target.join(".oblivion-transfers"),
                &target,
                operation,
                &opening.safe_id,
                &opening.nonce,
                oblivion_transfer::native_files::Direction::Export,
                action,
            )?);
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
