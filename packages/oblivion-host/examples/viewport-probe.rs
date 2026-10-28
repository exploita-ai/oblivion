//! Disposable laboratory entrypoint for the actual filtered terminal bridge.
use std::io::BufRead;
use std::num::NonZeroU16;
use std::os::unix::net::UnixStream;

fn main() -> oblivion_host::control::Result<()> {
    oblivion_host::control::protect()?;
    let path = std::env::args().nth(1).ok_or("socket_argument_required")?;
    if path == "--screen" {
        let mut parser = vt100::Parser::new(
            NonZeroU16::new(24).unwrap(),
            NonZeroU16::new(80).unwrap(),
            0,
        );
        for line in std::io::stdin().lock().lines() {
            let value: serde_json::Value = serde_json::from_str(&line?)?;
            if value["type"] != "frame" {
                println!("{value}");
                continue;
            }
            let rows = NonZeroU16::try_from(u16::try_from(
                value["rows"].as_u64().ok_or("invalid_rows")?,
            )?)?;
            let cols = NonZeroU16::try_from(u16::try_from(
                value["cols"].as_u64().ok_or("invalid_cols")?,
            )?)?;
            if value["full"] == true {
                parser = vt100::Parser::new(rows, cols, 0);
            }
            parser.screen_mut().set_size(rows, cols);
            parser.process(value["data"].as_str().ok_or("invalid_frame")?.as_bytes());
            println!(
                "{}",
                serde_json::json!({"type":"snapshot", "text":parser.screen().contents()})
            );
        }
        return Ok(());
    }
    oblivion_host::chat_screen::bridge_terminal(UnixStream::connect(path)?)
}
