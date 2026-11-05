//! Human copy review shared by native frontends. Local paths are rendered only
//! here; wire manifests and progress events contain logical names instead.
use oblivion_transfer::native_file_events::Summary;
use oblivion_transfer::native_files::{Context, Direction};
use oblivion_transfer::selection::Plan;
use std::io::{self, Write};
use std::path::Path;

pub fn write(
    output: &mut impl Write,
    context: &Context,
    summary: &Summary,
    plan: &Plan,
    sources: &[String],
    destination: Option<&Path>,
) -> io::Result<()> {
    writeln!(
        output,
        "Review {} · Safe {}",
        if context.direction == Direction::Import {
            "import"
        } else {
            "export"
        },
        context.safe_id
    )?;
    for mapping in &plan.mappings {
        let source = sources
            .get(mapping.input_index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid_file_mapping"))?;
        if let Some(owner) = mapping.covered_by {
            writeln!(
                output,
                "  {}. {source:?} · included in selection {}",
                mapping.input_index + 1,
                owner + 1
            )?;
            continue;
        }
        let target = if plan.mappings.len() == 1 {
            context.name.clone()
        } else {
            format!(
                "{}/{}",
                context.name,
                mapping.alias.as_deref().ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid_file_mapping"
                ))?
            )
        };
        writeln!(
            output,
            "  {}. {source:?} → {target:?}",
            mapping.input_index + 1
        )?;
    }
    match destination {
        Some(path) => {
            writeln!(output, "To this computer · {:?}", path.join(&context.name))?;
            writeln!(
                output,
                "Exported files use the destination filesystem's protection."
            )?;
        }
        None => writeln!(output, "To the Safe · workspace/{:?}", context.name)?,
    }
    writeln!(
        output,
        "{} files · {} folders · {} bytes",
        summary.files, summary.directories, summary.bytes
    )?;
    writeln!(output, "Manifest SHA-256 {}", summary.manifest_sha256)
}
