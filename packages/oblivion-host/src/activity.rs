//! Desktop-only activity reports contain opening identities, never input bytes.
use crate::{autolock, control, scope};
pub use oblivion_cli::activity::HumanInput;
use std::io::Read;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::time::{Duration, Instant};

pub struct Reporter {
    sender: SyncSender<Instant>,
    sent: Option<Instant>,
}

impl Reporter {
    pub fn current_safe(id: &str) -> control::Result<Self> {
        Ok(Self::spawn(oblivion_cli::activity::current_safe(
            &mut control::Client::new(),
            scope::current(),
            id,
        )?))
    }

    pub fn current_host() -> control::Result<Option<Self>> {
        Ok(oblivion_cli::activity::current_host(&mut control::Client::new())?.map(Self::spawn))
    }

    fn spawn(activity: autolock::Activity) -> Self {
        let (sender, receiver) = sync_channel::<Instant>(1);
        std::thread::spawn(move || {
            let mut sent: Option<Instant> = None;
            for at in receiver {
                // A stalled controller must not receive replayed activity after
                // the original input is stale. No input content enters this queue.
                if at.elapsed() <= Duration::from_secs(2)
                    && sent.is_none_or(|previous| previous.elapsed() >= Duration::from_secs(1))
                {
                    sent = Some(Instant::now());
                    let _ = oblivion_cli::activity::report(&mut control::Client::new(), &activity);
                }
            }
        });
        Self { sender, sent: None }
    }

    pub fn touch(&mut self, now: Instant) {
        if self
            .sent
            .is_some_and(|sent| now.saturating_duration_since(sent) < Duration::from_secs(1))
        {
            return;
        }
        if self.sender.try_send(now).is_ok() {
            self.sent = Some(now)
        }
    }
}

pub fn forward_stdin() -> control::Result<i32> {
    let mut bytes = Vec::new();
    std::io::stdin().take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err("Activity report is too large".into());
    }
    let activity: autolock::Activity = serde_json::from_slice(&bytes)?;
    oblivion_cli::activity::report(&mut control::Client::new(), &activity)?;
    Ok(0)
}
