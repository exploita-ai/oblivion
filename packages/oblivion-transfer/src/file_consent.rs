//! Pure consent for one reviewed Files copy. Adapters own pipe readiness,
//! deadlines, cancellation handles and delivery; all input/state policy is here.
use crate::Receipt;
use crate::native_file_events::{self, Event, Identity, Input, Outcome, Phase, Summary};
use crate::native_files::Direction;
use crate::selection::{MAPPING_PAGE, Plan};
use std::io;
use std::time::{Duration, Instant};

#[derive(Debug, Eq, PartialEq)]
pub enum Stage {
    Preparing,
    Review(String),
    Approved,
    CancelledBeforeCopy,
    Cancelled,
    Failed,
}

pub struct Admission {
    identity: Identity,
    stage: Stage,
    line: Vec<u8>,
}

impl Admission {
    pub fn stage(&self) -> &Stage {
        &self.stage
    }
    pub fn pending(&self) -> usize {
        self.line.len()
    }

    /// Parse under the same mutex used to arm Review. True requires immediate
    /// revocation by the adapter, including when cancellation precedes approval.
    pub fn feed(&mut self, bytes: &[u8]) -> io::Result<bool> {
        let result = self.receive(bytes);
        if result.is_err() {
            self.fail();
        }
        result
    }

    fn receive(&mut self, bytes: &[u8]) -> io::Result<bool> {
        if matches!(
            self.stage,
            Stage::CancelledBeforeCopy | Stage::Cancelled | Stage::Failed
        ) {
            return Err(revoked());
        }
        for byte in bytes {
            if self.line.len() >= native_file_events::LINE_LIMIT {
                return Err(revoked());
            }
            self.line.push(*byte);
            if *byte != b'\n' {
                continue;
            }
            match native_file_events::input(&self.line, &self.identity.operation_id)? {
                Input::Approve {
                    manifest_sha256, ..
                } => {
                    if !matches!(&self.stage, Stage::Review(expected) if *expected == manifest_sha256)
                    {
                        return Err(revoked());
                    }
                    self.stage = Stage::Approved;
                }
                Input::Cancel { .. } => {
                    self.stage = if matches!(self.stage, Stage::Preparing | Stage::Review(_)) {
                        Stage::CancelledBeforeCopy
                    } else {
                        Stage::Cancelled
                    };
                    self.line.clear();
                    return Ok(true);
                }
            }
            self.line.clear();
        }
        Ok(false)
    }

    pub fn fail(&mut self) {
        self.stage = Stage::Failed;
    }
    pub fn eof(&mut self) -> io::Result<()> {
        self.fail();
        Err(revoked())
    }
}

/// Mapping is committed only after every bounded page was delivered. A failed
/// or cancelled delivery cannot arm Review over an incomplete mapping.
pub struct Mapping {
    identity: Identity,
    digest: String,
    count: usize,
    events: Vec<Event>,
}
impl Mapping {
    pub fn events(&self) -> &[Event] {
        &self.events
    }
}

pub enum Review {
    Waiting,
    CancelledBeforeCopy,
    Ready(Event),
}

pub struct Flow {
    identity: Identity,
    direction: Direction,
    name: String,
    summary: Option<Summary>,
    mapping: Option<(String, usize)>,
    progress: Option<(Phase, u64, Instant)>,
    finished: bool,
}

impl Flow {
    pub fn new(
        identity: Identity,
        direction: Direction,
        name: String,
    ) -> io::Result<(Self, Admission)> {
        identity.validate()?;
        let admission = Admission {
            identity: identity.clone(),
            stage: Stage::Preparing,
            line: Vec::new(),
        };
        Ok((
            Self {
                identity,
                direction,
                name,
                summary: None,
                mapping: None,
                progress: None,
                finished: false,
            },
            admission,
        ))
    }

    fn bound(&self, admission: &Admission) -> io::Result<()> {
        if self.identity != admission.identity || self.finished {
            return Err(revoked());
        }
        Ok(())
    }

    pub fn plan(&self, admission: &Admission, plan: &Plan) -> io::Result<Mapping> {
        self.bound(admission)?;
        if self.mapping.is_some() || !matches!(admission.stage, Stage::Preparing) {
            return Err(revoked());
        }
        let digest = plan.sha256()?;
        let events = plan
            .mappings
            .chunks(MAPPING_PAGE)
            .enumerate()
            .map(|(page, entries)| Event::Mapping {
                identity: self.identity.clone(),
                start: page * MAPPING_PAGE,
                total: plan.mappings.len(),
                selected: plan.selected.clone(),
                entries: entries.to_vec(),
                mapping_sha256: digest.clone(),
            })
            .collect();
        Ok(Mapping {
            identity: self.identity.clone(),
            digest,
            count: plan.mappings.len(),
            events,
        })
    }

    pub fn mapped(&mut self, admission: &Admission, mapping: Mapping) -> io::Result<()> {
        self.bound(admission)?;
        if mapping.identity != self.identity
            || self.mapping.is_some()
            || !matches!(admission.stage, Stage::Preparing)
        {
            return Err(revoked());
        }
        self.mapping = Some((mapping.digest, mapping.count));
        Ok(())
    }

    /// `input_ready` must be observed under this Admission's lock. Waiting
    /// drains even partial prebuffered input before approval can become valid.
    pub fn review(
        &mut self,
        admission: &mut Admission,
        summary: &Summary,
        input_ready: bool,
    ) -> io::Result<Review> {
        summary.validate()?;
        self.bound(admission)?;
        match admission.stage {
            Stage::CancelledBeforeCopy => return Ok(Review::CancelledBeforeCopy),
            Stage::Preparing => {}
            _ => return Err(revoked()),
        }
        if input_ready || admission.pending() != 0 {
            return Ok(Review::Waiting);
        }
        if !self.mapping.as_ref().is_some_and(|(digest, count)| {
            *digest == summary.mapping_sha256
                && summary.files + summary.directories == summary.entries - usize::from(*count > 1)
        }) {
            return Err(revoked());
        }
        admission.stage = Stage::Review(summary.manifest_sha256.clone());
        self.summary = Some(summary.clone());
        Ok(Review::Ready(Event::Review {
            identity: self.identity.clone(),
            direction: self.direction,
            name: self.name.clone(),
            summary: summary.clone(),
        }))
    }

    /// Time is provided by the adapter. Suppressed samples still advance the
    /// monotonic byte check; totals never imply a successful copy.
    pub fn progress(
        &mut self,
        admission: &Admission,
        phase: Phase,
        bytes: u64,
        now: Instant,
    ) -> io::Result<Option<Event>> {
        self.bound(admission)?;
        if !matches!(admission.stage, Stage::Approved) {
            return Err(revoked());
        }
        let summary = self.summary.as_ref().ok_or_else(revoked)?;
        if bytes > summary.bytes
            || self.progress.as_ref().is_some_and(|(last, sent, _)| {
                bytes < *sent || *last == Phase::Finalizing && phase != Phase::Finalizing
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid_file_progress",
            ));
        }
        let event = Event::Progress {
            identity: self.identity.clone(),
            phase,
            bytes,
            total_bytes: summary.bytes,
        };
        event.validate()?;
        if let Some((last, sent, at)) = self.progress {
            if last == phase
                && (bytes != summary.bytes || bytes == sent)
                && now.saturating_duration_since(at) < Duration::from_millis(100)
            {
                self.progress = Some((phase, bytes, at));
                return Ok(None);
            }
        }
        self.progress = Some((phase, bytes, now));
        Ok(Some(event))
    }

    pub fn finish(
        &mut self,
        admission: &Admission,
        outcome: Outcome,
        receipt: Option<Receipt>,
    ) -> io::Result<Event> {
        self.bound(admission)?;
        if outcome == Outcome::Completed
            && (!matches!(admission.stage, Stage::Approved)
                || !self
                    .summary
                    .as_ref()
                    .zip(receipt.as_ref())
                    .is_some_and(|(summary, receipt)| summary.matches(receipt, &self.identity)))
        {
            return Err(revoked());
        }
        if outcome == Outcome::CancelledBeforeCopy
            && !matches!(admission.stage, Stage::CancelledBeforeCopy)
        {
            return Err(revoked());
        }
        let event = Event::Finished {
            identity: self.identity.clone(),
            outcome,
            receipt,
        };
        event.validate()?;
        self.finished = true;
        Ok(event)
    }
}

pub fn revoked() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "file_events_revoked")
}
