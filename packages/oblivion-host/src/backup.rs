//! Current personal-backup wire model, specialized to the validated host slot.
pub use oblivion_wire::backup::{Exported, Finish, Finished, Imported, Kind, Outcome};
pub type Entry = oblivion_wire::backup::Entry<crate::scope::Slot>;
pub type Status = oblivion_wire::backup::Status<crate::scope::Slot>;
