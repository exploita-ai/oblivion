#![cfg(unix)]
mod support;
use oblivion_transfer::native_files::{Context, Direction, TransfersQuery};
use oblivion_transfer::stream::operations;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use support::Tree;

const SAFE: &str = "11111111111111111111111111111111";
const OPENING: &str = "22222222222222222222222222222222";

#[test]
fn bounded_inventory_survives_new_opening_and_skips_unrelated_or_invalid_records() {
    let inbox = Tree::new();
    let target = Tree::new();
    let other = Tree::new();
    for index in 1..=6 {
        let context = Context {
            id: format!("{index:032x}"),
            safe_id: if index == 2 {
                "3".repeat(32)
            } else {
                SAFE.into()
            },
            opening: OPENING.into(),
            direction: if index == 4 {
                Direction::Export
            } else {
                Direction::Import
            },
            name: format!("item{index}"),
        };
        operations::begin(
            &inbox.0,
            if index == 5 { &other.0 } else { &target.0 },
            &context,
        )
        .unwrap();
    }
    fs::write(
        inbox
            .0
            .join("operations")
            .join(format!("{:032x}", 3))
            .join("context.json"),
        b"not-json",
    )
    .unwrap();
    let mut query = TransfersQuery {
        safe_id: SAFE.into(),
        opening: "4".repeat(32),
        direction: Direction::Import,
        after: None,
        limit: 2,
    };
    let first = operations::inventory(&inbox.0, &target.0, &query).unwrap();
    first.validate(&query).unwrap();
    assert_eq!(first.entries.len(), 1);
    assert_eq!(first.entries[0].operation_id, format!("{:032x}", 1));
    assert_eq!(first.entries[0].source_opening, OPENING);
    assert_eq!(first.skipped, 1);
    query.after = first.next_cursor;
    let second = operations::inventory(&inbox.0, &target.0, &query).unwrap();
    second.validate(&query).unwrap();
    assert!(second.entries.is_empty());
    assert_eq!(second.skipped, 2);
    query.after = second.next_cursor;
    let third = operations::inventory(&inbox.0, &target.0, &query).unwrap();
    assert_eq!(third.entries.len(), 1);
    assert_eq!(third.entries[0].operation_id, format!("{:032x}", 6));
    assert_eq!(third.skipped, 1);
    assert!(third.next_cursor.is_none());
}

#[test]
fn missing_inventory_is_empty_but_unsafe_or_busy_roots_are_errors() {
    let inbox = Tree::new();
    let target = Tree::new();
    let query = TransfersQuery {
        safe_id: SAFE.into(),
        opening: OPENING.into(),
        direction: Direction::Export,
        after: None,
        limit: 8,
    };
    assert!(
        operations::inventory(&inbox.0.join("absent"), &target.0, &query)
            .unwrap()
            .entries
            .is_empty()
    );
    fs::set_permissions(&inbox.0, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(operations::inventory(&inbox.0, &target.0, &query).is_err());
    fs::set_permissions(&inbox.0, fs::Permissions::from_mode(0o700)).unwrap();
    let lock = File::open(&inbox.0).unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    assert!(operations::inventory(&inbox.0, &target.0, &query).is_err());
}
