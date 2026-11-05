//! Unix endpoints for the shared personal-backup workflow. The source and
//! output authorities are also used by Windows; no Safe filesystem is mounted.
use oblivion_cli::backup::{Command, Native};
use oblivion_host::{control, scope};
use oblivion_transfer::backup::Source;
use oblivion_transfer::channel::Channel;
use oblivion_transfer::local_file::{Output, Target};
use oblivion_transfer::{MAX_ENCRYPTED_VOLUME_BYTES, Receipt, stream};
use oblivion_wire::backup::{Exported, Imported};
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;

pub fn run(command: Command) -> control::Result<i32> {
    oblivion_cli::backup::run(
        &mut super::UnixRuntime::new(),
        command,
        &mut io::stdout(),
        &mut io::stderr(),
    )
}

impl Native for super::UnixRuntime {
    type Source = Source;
    type Destination = Target;
    type Output = Output;

    fn prepare_import(&mut self, path: &str) -> control::Result<Source> {
        Ok(Source::open(Path::new(path), MAX_ENCRYPTED_VOLUME_BYTES)?)
    }

    fn source_bytes(source: &Source) -> u64 {
        source.bytes()
    }

    fn prepare_export(&mut self, path: &str) -> control::Result<Target> {
        Ok(Target::new(Path::new(path))?)
    }

    fn send_import(
        &mut self,
        source: &mut Source,
        prepared: &Imported,
        slot: scope::Slot,
    ) -> control::Result<Receipt> {
        scope::within(slot, || {
            let (connection, lease, _) = control::attach_backup(&prepared.transaction)?;
            let mut channel = Channel::new(
                File::from(OwnedFd::from(connection)),
                Duration::from_secs(3600),
            )?;
            let result = stream::send(&mut channel, source, &prepared.transaction);
            drop(channel);
            drop(lease);
            Ok(result?)
        })
    }

    fn receive_export(
        &mut self,
        destination: Target,
        prepared: &Exported,
        slot: scope::Slot,
    ) -> control::Result<(Output, Receipt)> {
        scope::within(slot, || {
            let output = destination.create(&prepared.transaction)?;
            let (connection, lease, _) = control::attach_backup(&prepared.transaction)?;
            let mut channel = Channel::new(
                File::from(OwnedFd::from(connection)),
                Duration::from_secs(3600),
            )?;
            let result = stream::download_open_file(
                &mut channel,
                output.copy_file()?,
                prepared.bytes,
                &prepared.transaction,
            );
            drop(channel);
            drop(lease);
            Ok((output, result?))
        })
    }

    fn publish_export(&mut self, mut output: Output) -> control::Result<String> {
        output.publish()?;
        Ok(output.path().to_string_lossy().into_owned())
    }
}
