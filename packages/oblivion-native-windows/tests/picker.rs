#![cfg(windows)]

use std::process::{Child, Command, Stdio};
use std::ptr::null_mut;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BM_CLICK, EnumWindows, GW_OWNER, GetDlgItem, GetWindow, GetWindowThreadProcessId,
    IsWindowVisible, PostMessageW,
};

#[test]
fn picker_rejects_extra_arguments_without_starting_the_window() {
    let result = Command::new(env!("CARGO_BIN_EXE_oblivion-vm"))
        .args(["pick-files", "unexpected"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result.stderr).unwrap(),
        serde_json::json!({ "event": "invalid_arguments" })
    );
}

#[test]
#[ignore = "requires an ordinary-user interactive Windows desktop"]
fn owner_eof_dismisses_the_palette_and_its_native_dialogs() {
    // The palette, Choose files, and Choose folder each keep a real Win32
    // message pump active. No file is selected and no runtime is started.
    for button in [None, Some(10), Some(11)] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_oblivion-vm"))
            .arg("pick-files")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let window = wait_for(&mut child, |pid| owned_window(pid, null_mut()));
        if let Some(button) = button {
            let control = unsafe { GetDlgItem(window, button) };
            if control.is_null() || unsafe { PostMessageW(control, BM_CLICK, 0, 0) } == 0 {
                stop(&mut child);
                panic!("picker button unavailable");
            }
            wait_for(&mut child, |pid| owned_window(pid, window));
        }
        drop(child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                stop(&mut child);
                panic!("picker did not close after owner EOF");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            serde_json::json!({ "paths": [] })
        );
    }
}

fn wait_for(child: &mut Child, observe: impl Fn(u32) -> HWND) -> HWND {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let window = observe(child.id());
        if !window.is_null() {
            return window;
        }
        if child.try_wait().unwrap().is_some() || Instant::now() >= deadline {
            stop(child);
            panic!("picker window unavailable");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn owned_window(pid: u32, owner: HWND) -> HWND {
    struct Find {
        pid: u32,
        owner: HWND,
        result: HWND,
    }

    unsafe extern "system" fn observe(window: HWND, data: LPARAM) -> i32 {
        let search = unsafe { &mut *(data as *mut Find) };
        let mut pid = 0;
        unsafe { GetWindowThreadProcessId(window, &mut pid) };
        if pid == search.pid
            && unsafe { IsWindowVisible(window) } != 0
            && unsafe { GetWindow(window, GW_OWNER) } == search.owner
        {
            search.result = window;
            return 0;
        }
        1
    }

    let mut search = Find {
        pid,
        owner,
        result: null_mut(),
    };
    unsafe { EnumWindows(Some(observe), (&mut search as *mut Find) as LPARAM) };
    search.result
}
