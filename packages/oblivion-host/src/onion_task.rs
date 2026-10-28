//! One bounded file-control RPC, off the Tor/session ownership loop. The owner
//! supplies the channel's deadline and cancellation descriptors before launch.
use oblivion_transfer::channel::Channel;
use oblivion_transfer::endpoint::{read_message, write_message};
use serde::{Deserialize, Serialize};
use std::io;
use std::thread::JoinHandle;

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    Backup {
        ttl_seconds: u16,
    },
    Receive {
        ttl_seconds: u16,
    },
    PrepareShare {},
    Share {
        receipt: oblivion_transfer::Receipt,
        paths: Vec<String>,
        ttl_seconds: u16,
    },
    Freeze {},
    Source {},
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Receiving,
    Staging,
    Sharing,
    Review,
    Copying,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    ok: bool,
    phase: Phase,
}

pub struct Task(JoinHandle<io::Result<()>>);

impl Task {
    pub fn start(mut channel: Channel, command: Command) -> io::Result<Self> {
        std::thread::Builder::new()
            .name("onion-file-control".into())
            .spawn(move || {
                write_message(&mut channel, &command)?;
                let reply: Reply = read_message(&mut channel, 4096)?;
                let expected = match command {
                    Command::Receive { .. } => Phase::Receiving,
                    Command::PrepareShare {} => Phase::Staging,
                    Command::Share { .. } => Phase::Sharing,
                    Command::Backup { .. } => Phase::Sharing,
                    Command::Freeze {} => Phase::Review,
                    Command::Source {} => Phase::Copying,
                };
                if !reply.ok || reply.phase != expected {
                    return Err(io::Error::other("onion_worker_failed"));
                }
                Ok(())
            })
            .map(Self)
    }

    pub fn is_finished(&self) -> bool {
        self.0.is_finished()
    }

    pub fn join(self) -> io::Result<()> {
        self.0
            .join()
            .map_err(|_| io::Error::other("onion_worker_failed"))?
    }
}
