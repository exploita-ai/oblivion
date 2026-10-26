mod support;
use oblivion_transfer::browser::{self, Request};
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use support::Tree;

#[test]
fn document_browser_is_confined_and_does_not_follow_links() {
    let tree = Tree::new();
    fs::create_dir(tree.0.join("workspace")).unwrap();
    fs::create_dir(tree.0.join("imports")).unwrap();
    fs::create_dir(tree.0.join("state")).unwrap();
    fs::write(tree.0.join("state/secret"), b"private").unwrap();
    symlink("../state", tree.0.join("workspace/link")).unwrap();
    fs::write(tree.0.join("workspace/valid.txt"), b"hello").unwrap();
    fs::write(tree.0.join("workspace/bad\nname"), b"hidden").unwrap();
    // APFS rejects non-UTF8 names at creation; ext4 permits them.
    #[cfg(target_os = "linux")]
    fs::write(
        tree.0
            .join("workspace")
            .join(std::ffi::OsString::from_vec(vec![0xff])),
        b"hidden",
    )
    .unwrap();
    let page = browser::list(
        &tree.0,
        &Request {
            path: "".into(),
            after: None,
            limit: 100,
        },
        true,
    )
    .unwrap();
    assert_eq!(
        page.entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["imports", "workspace"]
    );
    for path in [
        "state",
        "../state",
        "/etc",
        "workspace/../state",
        "workspace/link",
        "workspace//x",
    ] {
        assert!(
            browser::list(
                &tree.0,
                &Request {
                    path: path.into(),
                    after: None,
                    limit: 100
                },
                true
            )
            .is_err()
        );
    }
    let request = Request {
        path: "workspace".into(),
        after: None,
        limit: 100,
    };
    let page = browser::list(&tree.0, &request, true).unwrap();
    page.validate(&request).unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].name, "valid.txt");
    assert_eq!(page.entries[0].bytes, 5);
    assert_eq!(page.skipped, if cfg!(target_os = "linux") { 3 } else { 2 });
}

#[test]
fn bounded_pages_visit_large_directories_without_duplicates() {
    let tree = Tree::new();
    for index in 0..2307 {
        fs::write(tree.0.join(format!("file-{index:04}")), b"").unwrap();
    }
    let mut after = None;
    let mut names = Vec::new();
    loop {
        let request = Request {
            path: "".into(),
            after,
            limit: 73,
        };
        let page = browser::list(&tree.0, &request, false).unwrap();
        page.validate(&request).unwrap();
        names.extend(page.entries.into_iter().map(|entry| entry.name));
        after = page.next;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(names.len(), 2307);
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        browser::list(
            &tree.0,
            &Request {
                path: "".into(),
                after: None,
                limit: 101
            },
            false
        )
        .is_err()
    );
    assert!(
        browser::list(
            &tree.0,
            &Request {
                path: "".into(),
                after: Some("../x".into()),
                limit: 100
            },
            false
        )
        .is_err()
    );
}
