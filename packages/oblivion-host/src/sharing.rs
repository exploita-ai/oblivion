//! Current Share RPC values. The shared model owns the schema; concrete
//! controller slots remain validated by the Host's own slot type.
pub use oblivion_share::control::{
    Abort, Begin, Begun, Commit, Committed, Destination, Discard, Finish, Open, Outcome, Parent,
};
pub type Opened = oblivion_share::control::Opened<crate::scope::Slot>;
pub type Status = oblivion_share::control::Status<crate::scope::Slot>;
