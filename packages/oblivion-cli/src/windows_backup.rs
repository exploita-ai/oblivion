//! Native Windows transport for the common personal-backup workflow. Files
//! remain ciphertext; the controller alone authenticates and restores the Safe.
use crate::backup::Native;
use crate::controller::Result;
use crate::windows::Runtime;
use oblivion_transfer::backup::{Output, OutputTarget, Source};
use oblivion_transfer::{MAX_ENCRYPTED_VOLUME_BYTES, Receipt, stream};
use oblivion_wire::backup::{Exported, Imported};
use oblivion_wire::slot::Slot;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

impl Native for Runtime {
    type Source = Source;
    type Destination = OutputTarget;
    type Output = Output;

    fn prepare_import(&mut self, path: &str) -> Result<Source> {
        Ok(Source::open(Path::new(path), MAX_ENCRYPTED_VOLUME_BYTES)?)
    }

    fn source_bytes(source: &Source) -> u64 {
        source.bytes()
    }

    fn prepare_export(&mut self, path: &str) -> Result<OutputTarget> {
        Ok(OutputTarget::new(Path::new(path))?)
    }

    fn send_import(
        &mut self,
        source: &mut Source,
        prepared: &Imported,
        slot: Slot,
    ) -> Result<Receipt> {
        let mut attachment = self.attach_backup(
            &prepared.transaction,
            slot,
            Arc::new(AtomicBool::new(false)),
        )?;
        let result = stream::send(attachment.stream(), source, &prepared.transaction);
        // EOF ends the backup attachment. AgentRelease is a different protocol;
        // shared orchestration checks the controller's Copied state afterwards.
        attachment.close()?;
        Ok(result?)
    }

    fn receive_export(
        &mut self,
        destination: OutputTarget,
        prepared: &Exported,
        slot: Slot,
    ) -> Result<(Output, Receipt)> {
        let output = destination.create(&prepared.transaction)?;
        let mut attachment = self.attach_backup(
            &prepared.transaction,
            slot,
            Arc::new(AtomicBool::new(false)),
        )?;
        let result = (|| {
            stream::download_open_file(
                attachment.stream(),
                output.copy_file()?,
                prepared.bytes,
                &prepared.transaction,
            )
        })();
        attachment.close()?;
        Ok((output, result?))
    }

    fn publish_export(&mut self, mut output: Output) -> Result<String> {
        output.publish()?;
        Ok(output.path().to_string_lossy().into_owned())
    }
}
