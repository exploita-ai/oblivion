//! Windows controller adapter for the common frontend. The trusted runtime
//! supervisor supplies the elected runtime ID; discovery/startup live above it.
use crate::controller::{Call, Controller, Result};
use oblivion_native_windows::client;
use oblivion_wire::control::Request;
use oblivion_wire::slot::Slot;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

pub struct Client {
    transport: client::Client,
    cancelled: Arc<AtomicBool>,
}

/// A clonable, one-way cancellation capability for a synchronous request or
/// attachment. A signal/input owner can hold it while the client is borrowed.
#[derive(Clone)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Client {
    pub fn new(runtime_id: &str) -> Result<Self> {
        Ok(Self {
            transport: client::Client::new(runtime_id)?,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Cancellation revokes this client instance. A new opening must construct
    /// a new client rather than clearing an old cancellation capability.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn cancellation(&self) -> Cancellation {
        Cancellation(Arc::clone(&self.cancelled))
    }

    pub fn attach(&self, call: Call<'_, Slot>) -> Result<(client::Channel, String)> {
        if !call.operation.is_attachment() {
            return Err("invalid_attachment".into());
        }
        self.transport.attach(
            header(&call)?,
            call.secret,
            Arc::clone(&self.cancelled),
            Instant::now() + call.operation.response_budget(),
        )
    }
}

impl Controller for Client {
    type Slot = Slot;

    fn request(&mut self, call: Call<'_, Self::Slot>) -> Result<String> {
        self.transport.request(
            header(&call)?,
            call.secret,
            Arc::clone(&self.cancelled),
            Instant::now() + call.operation.response_budget(),
        )
    }
}

fn header(call: &Call<'_, Slot>) -> Result<Request<Slot>> {
    Ok(Request {
        operation: call.operation,
        slot: call.slot.unwrap_or(Slot::ZERO),
        expected_session: call.expected_session.map(str::to_owned),
        session: call.session.map(str::to_owned),
        secret_len: u32::try_from(call.secret.len()).map_err(|_| "secret_too_large")?,
    })
}
