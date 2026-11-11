//! Ordinary-user file selection. This process owns a window and a lifetime
//! pipe, and returns names only. The Files caller reviews and opens them later.
use crate::{Error, Result, lifetime::Lifetime, security};
use std::cell::{Cell, RefCell};
use std::io::{self, Write};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    COLOR_WINDOW, DEFAULT_GUI_FONT, GetStockObject, GetSysColorBrush,
};
use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::WindowsProgramming::{
    DRIVE_CDROM, DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOVABLE,
};
use windows_sys::Win32::UI::Controls::Dialogs::{
    CommDlgExtendedError, GetOpenFileNameW, OFN_ALLOWMULTISELECT, OFN_DONTADDTORECENT,
    OFN_ENABLEHOOK, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_HIDEREADONLY, OFN_NOCHANGEDIR,
    OFN_NODEREFERENCELINKS, OPENFILENAMEW,
};
use windows_sys::Win32::UI::Shell::{
    BFFM_INITIALIZED, BIF_DONTGOBELOWDOMAIN, BIF_NEWDIALOGSTYLE, BIF_NONEWFOLDERBUTTON,
    BIF_NOTRANSLATETARGETS, BIF_RETURNONLYFSDIRS, BROWSEINFOW, DragFinish, DragQueryFileW, HDROP,
    SHBrowseForFolderW, SHGetPathFromIDListEx,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BS_DEFPUSHBUTTON, CREATESTRUCTW, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW, DestroyWindow,
    DispatchMessageW, GWLP_USERDATA, GetMessageW, GetParent, GetWindowLongPtrW, IDC_ARROW,
    IDCANCEL, IsDialogMessageW, LoadCursorW, MSG, PostMessageW, PostQuitMessage, RegisterClassW,
    SW_SHOW, SendMessageW, SetTimer, SetWindowLongPtrW, ShowWindow, TranslateMessage, WM_CLOSE,
    WM_COMMAND, WM_DESTROY, WM_DROPFILES, WM_INITDIALOG, WM_NCCREATE, WM_SETFONT, WM_TIMER,
    WNDCLASSW, WS_CAPTION, WS_CHILD, WS_EX_ACCEPTFILES, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};
use windows_sys::w;

const MAX_PATHS: usize = 128;
const MAX_BYTES: usize = 64 * 1024;
const MAX_WIDE_PATH: usize = 32767;
const FILES: u16 = 10;
const FOLDER: u16 = 11;
const CANCEL: u16 = IDCANCEL as u16;
const OWNER_TIMER: usize = 1;
const CLASS: *const u16 = w!("OblivionFilesPicker");
const INVALID_PATH: Error = Error("picker_invalid_local_path");
const WINDOW_ERROR: Error = Error("picker_window_failed");

pub fn run() -> Result<()> {
    if security::elevated()? {
        return Err(Error("picker_requires_ordinary_user"));
    }
    let paths = match Lifetime::inherited() {
        Ok(owner) => choose(owner)?,
        Err(Error("supervisor_lifetime_lost")) => Vec::new(),
        Err(_) => return Err(Error("picker_owner_pipe_required")),
    };
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, &serde_json::json!({ "paths": paths }))
        .map_err(|_| Error("picker_output_failed"))?;
    output
        .write_all(b"\n")
        .map_err(|_| Error("picker_output_failed"))?;
    output.flush().map_err(|_| Error("picker_output_failed"))
}

struct Picker {
    owner: Lifetime,
    dialog: Cell<HWND>,
    result: RefCell<Option<Result<Vec<String>>>>,
}

impl Picker {
    fn finish(&self, window: HWND, result: Result<Vec<String>>) {
        self.result.borrow_mut().get_or_insert(result);
        let dialog = self.dialog.get();
        if dialog.is_null() {
            unsafe { DestroyWindow(window) };
        } else {
            // The native modal loop keeps dispatching this window's timer.
            unsafe { PostMessageW(dialog, WM_CLOSE, 0, 0) };
        }
    }
}

fn choose(owner: Lifetime) -> Result<Vec<String>> {
    let picker = Picker {
        owner,
        dialog: Cell::new(null_mut()),
        result: RefCell::new(None),
    };
    let instance = unsafe { GetModuleHandleW(null()) };
    let class = WNDCLASSW {
        lpfnWndProc: Some(window_message),
        hInstance: instance,
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        hbrBackground: unsafe { GetSysColorBrush(COLOR_WINDOW) },
        lpszClassName: CLASS,
        ..Default::default()
    };
    if instance.is_null() || unsafe { RegisterClassW(&class) } == 0 {
        return Err(WINDOW_ERROR);
    }
    let window = unsafe {
        CreateWindowExW(
            WS_EX_ACCEPTFILES,
            CLASS,
            w!("Oblivion · Choose files"),
            WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            560,
            180,
            null_mut(),
            null_mut(),
            instance,
            (&picker as *const Picker).cast(),
        )
    };
    if window.is_null() {
        return Err(WINDOW_ERROR);
    }
    if create_controls(window, instance).is_err()
        || unsafe { SetTimer(window, OWNER_TIMER, 75, None) } == 0
    {
        unsafe { DestroyWindow(window) };
        return Err(WINDOW_ERROR);
    }
    unsafe { ShowWindow(window, SW_SHOW) };
    let mut message = MSG::default();
    loop {
        match unsafe { GetMessageW(&mut message, null_mut(), 0, 0) } {
            -1 => {
                unsafe { DestroyWindow(window) };
                return Err(WINDOW_ERROR);
            }
            0 => break,
            _ => {}
        }
        if unsafe { IsDialogMessageW(window, &message) } == 0 {
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
    unsafe { DestroyWindow(window) };
    if picker.owner.check().is_err() {
        return Ok(Vec::new());
    }
    picker.result.into_inner().ok_or(WINDOW_ERROR)?
}

fn create_controls(window: HWND, instance: HINSTANCE) -> Result<()> {
    let font = unsafe { GetStockObject(DEFAULT_GUI_FONT) };
    for (class, text, style, x, y, width, id) in [
        (
            w!("STATIC"),
            w!("Drop files or folders here, or choose them below."),
            0,
            24,
            24,
            490,
            0,
        ),
        (
            w!("BUTTON"),
            w!("Choose &files…"),
            WS_TABSTOP | BS_DEFPUSHBUTTON as u32,
            24,
            76,
            148,
            FILES,
        ),
        (
            w!("BUTTON"),
            w!("Choose f&older…"),
            WS_TABSTOP,
            184,
            76,
            148,
            FOLDER,
        ),
        (w!("BUTTON"), w!("Cancel"), WS_TABSTOP, 390, 76, 120, CANCEL),
    ] {
        let child = unsafe {
            CreateWindowExW(
                0,
                class,
                text,
                WS_CHILD | WS_VISIBLE | style,
                x,
                y,
                width,
                32,
                window,
                id as usize as _,
                instance,
                null(),
            )
        };
        if child.is_null() {
            return Err(WINDOW_ERROR);
        }
        unsafe { SendMessageW(child, WM_SETFONT, font as WPARAM, 1) };
    }
    Ok(())
}

unsafe extern "system" fn window_message(
    window: HWND,
    message: u32,
    word: WPARAM,
    parameter: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        let creation = unsafe { &*(parameter as *const CREATESTRUCTW) };
        unsafe { SetWindowLongPtrW(window, GWLP_USERDATA, creation.lpCreateParams as isize) };
    }
    let picker = unsafe { (GetWindowLongPtrW(window, GWLP_USERDATA) as *const Picker).as_ref() };
    if let Some(picker) = picker {
        match message {
            WM_DROPFILES => {
                let drop = Dropped(word as HDROP);
                if picker.dialog.get().is_null() && picker.result.borrow().is_none() {
                    picker.finish(window, drop.paths());
                }
                return 0;
            }
            WM_COMMAND => {
                let selected = word as u16;
                if selected == CANCEL {
                    picker.finish(window, Ok(Vec::new()));
                } else if matches!(selected, FILES | FOLDER)
                    && picker.dialog.get().is_null()
                    && picker.result.borrow().is_none()
                {
                    let paths = if selected == FILES {
                        choose_files(window, picker)
                    } else {
                        choose_folder(window, picker)
                    };
                    picker.dialog.set(null_mut());
                    if picker.result.borrow().is_some() || picker.owner.check().is_err() {
                        picker.finish(window, Ok(Vec::new()));
                    } else if let Some(paths) = paths.transpose() {
                        picker.finish(window, paths);
                    }
                }
                return 0;
            }
            WM_TIMER if word == OWNER_TIMER => {
                if picker.owner.check().is_err() {
                    picker.finish(window, Ok(Vec::new()));
                }
                return 0;
            }
            WM_CLOSE => {
                picker.finish(window, Ok(Vec::new()));
                return 0;
            }
            WM_DESTROY => {
                unsafe { PostQuitMessage(0) };
                return 0;
            }
            _ => {}
        }
    }
    unsafe { DefWindowProcW(window, message, word, parameter) }
}

struct Dropped(HDROP);
impl Drop for Dropped {
    fn drop(&mut self) {
        unsafe { DragFinish(self.0) };
    }
}

impl Dropped {
    fn paths(&self) -> Result<Vec<String>> {
        let count = unsafe { DragQueryFileW(self.0, u32::MAX, null_mut(), 0) };
        if count == 0 || count as usize > MAX_PATHS {
            return Err(Error("picker_selection_limit"));
        }
        let mut paths = Paths::default();
        for index in 0..count {
            let length = unsafe { DragQueryFileW(self.0, index, null_mut(), 0) } as usize;
            if length == 0 || length > MAX_WIDE_PATH {
                return Err(INVALID_PATH);
            }
            let mut buffer = vec![0; length + 1];
            if unsafe { DragQueryFileW(self.0, index, buffer.as_mut_ptr(), buffer.len() as u32) }
                != length as u32
            {
                return Err(INVALID_PATH);
            }
            paths.push(String::from_utf16(&buffer[..length]).map_err(|_| INVALID_PATH)?)?;
        }
        paths.local()
    }
}

fn choose_files(window: HWND, picker: &Picker) -> Result<Option<Vec<String>>> {
    let mut buffer = vec![0u16; MAX_BYTES + MAX_PATHS + 1];
    let mut dialog = OPENFILENAMEW {
        lStructSize: size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: window,
        lpstrFile: buffer.as_mut_ptr(),
        nMaxFile: buffer.len() as u32,
        lpstrTitle: w!("Choose files to import into Oblivion"),
        Flags: OFN_ALLOWMULTISELECT
            | OFN_DONTADDTORECENT
            | OFN_ENABLEHOOK
            | OFN_EXPLORER
            | OFN_FILEMUSTEXIST
            | OFN_HIDEREADONLY
            | OFN_NOCHANGEDIR
            | OFN_NODEREFERENCELINKS,
        lCustData: picker as *const Picker as LPARAM,
        lpfnHook: Some(files_dialog_message),
        ..Default::default()
    };
    if unsafe { GetOpenFileNameW(&mut dialog) } == 0 {
        if unsafe { CommDlgExtendedError() } == 0 {
            return Ok(None);
        }
        return Err(Error("picker_dialog_failed"));
    }
    parse_open_dialog(&buffer)?.local().map(Some)
}

unsafe extern "system" fn files_dialog_message(
    window: HWND,
    message: u32,
    _: WPARAM,
    parameter: LPARAM,
) -> usize {
    if message == WM_INITDIALOG {
        let dialog = unsafe { &*(parameter as *const OPENFILENAMEW) };
        let picker = unsafe { &*(dialog.lCustData as *const Picker) };
        // Explorer-style hooks run in the child dialog, not the modal parent.
        picker.dialog.set(unsafe { GetParent(window) });
    }
    0
}

fn choose_folder(window: HWND, picker: &Picker) -> Result<Option<Vec<String>>> {
    let mut display = [0u16; 260];
    let dialog = BROWSEINFOW {
        hwndOwner: window,
        pszDisplayName: display.as_mut_ptr(),
        lpszTitle: w!("Choose a local folder to import into Oblivion"),
        ulFlags: BIF_DONTGOBELOWDOMAIN
            | BIF_NEWDIALOGSTYLE
            | BIF_NONEWFOLDERBUTTON
            | BIF_NOTRANSLATETARGETS
            | BIF_RETURNONLYFSDIRS,
        lpfn: Some(folder_dialog_message),
        lParam: picker as *const Picker as LPARAM,
        ..Default::default()
    };
    if unsafe { CoInitializeEx(null(), COINIT_APARTMENTTHREADED as u32) } < 0 {
        return Err(Error("picker_dialog_failed"));
    }
    let selected = unsafe { SHBrowseForFolderW(&dialog) };
    let mut buffer = vec![0u16; MAX_WIDE_PATH + 1];
    let resolved = !selected.is_null()
        && unsafe { SHGetPathFromIDListEx(selected, buffer.as_mut_ptr(), buffer.len() as u32, 0) }
            != 0;
    unsafe {
        CoTaskMemFree(selected.cast());
        CoUninitialize();
    }
    if selected.is_null() {
        return Ok(None);
    }
    if !resolved {
        return Err(INVALID_PATH);
    }
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(INVALID_PATH)?;
    let mut paths = Paths::default();
    paths.push(String::from_utf16(&buffer[..end]).map_err(|_| INVALID_PATH)?)?;
    paths.local().map(Some)
}

unsafe extern "system" fn folder_dialog_message(
    window: HWND,
    message: u32,
    _: LPARAM,
    data: LPARAM,
) -> i32 {
    if message == BFFM_INITIALIZED {
        let picker = unsafe { &*(data as *const Picker) };
        picker.dialog.set(window);
    }
    0
}

fn parse_open_dialog(buffer: &[u16]) -> Result<Paths> {
    let mut fields = buffer.split_inclusive(|unit| *unit == 0);
    let mut read = || {
        let field = fields.next().ok_or(INVALID_PATH)?;
        let field = field.strip_suffix(&[0]).ok_or(INVALID_PATH)?;
        String::from_utf16(field).map_err(|_| INVALID_PATH)
    };
    let first = read()?;
    let mut leaf = read()?;
    let mut paths = Paths::default();
    if leaf.is_empty() {
        paths.push(first)?;
        return Ok(paths);
    }
    validate_path(&first)?;
    let directory = first.trim_end_matches(['\\', '/']);
    while !leaf.is_empty() {
        if leaf.contains(['\\', '/']) {
            return Err(INVALID_PATH);
        }
        paths.push(format!("{directory}\\{leaf}"))?;
        leaf = read()?;
    }
    Ok(paths)
}

#[derive(Default)]
struct Paths {
    items: Vec<String>,
    bytes: usize,
}

impl Paths {
    fn push(&mut self, path: String) -> Result<()> {
        validate_path(&path)?;
        if self.items.len() == MAX_PATHS || path.len() > MAX_BYTES - self.bytes {
            return Err(Error("picker_selection_limit"));
        }
        self.bytes += path.len();
        self.items.push(path);
        Ok(())
    }

    fn local(self) -> Result<Vec<String>> {
        for path in &self.items {
            let root = [u16::from(path.as_bytes()[0]), b':' as u16, b'\\' as u16, 0];
            if !matches!(
                unsafe { GetDriveTypeW(root.as_ptr()) },
                DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_CDROM | DRIVE_RAMDISK
            ) {
                return Err(INVALID_PATH);
            }
        }
        Ok(self.items)
    }
}

fn validate_path(path: &str) -> Result<()> {
    let bytes = path.as_bytes();
    if !matches!(bytes, [drive, b':', b'\\' | b'/', ..] if drive.is_ascii_alphabetic())
        || path[3..].contains([':', '*', '?', '<', '>', '"', '|'])
        || path[3..].split(['\\', '/']).any(|name| matches!(name, "." | ".."))
        || path.chars().any(|character| character.is_control() || matches!(
            character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        ))
    {
        return Err(INVALID_PATH);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Error, MAX_BYTES, MAX_PATHS, Paths, parse_open_dialog};

    fn decode(value: &str) -> Vec<String> {
        parse_open_dialog(&value.encode_utf16().collect::<Vec<_>>())
            .unwrap()
            .items
    }

    #[test]
    fn explorer_dialog_preserves_single_and_multiple_literal_paths() {
        assert_eq!(
            decode("C:\\work space\\a$'.txt\0\0"),
            ["C:\\work space\\a$'.txt"]
        );
        assert_eq!(
            decode("C:\\work space\0α.txt\0b$'.txt\0\0"),
            ["C:\\work space\\α.txt", "C:\\work space\\b$'.txt"]
        );
        assert_eq!(decode("C:\\\0a.txt\0\0"), ["C:\\a.txt"]);
    }

    #[test]
    fn rejects_virtual_remote_relative_and_controlled_paths() {
        for name in [
            r"\\server\share\file",
            r"\\?\C:\file",
            r"C:relative",
            r"C:\folder\..\file",
            r"C:\file:stream",
            "C:\\file\u{202e}.txt",
        ] {
            assert!(Paths::default().push(name.into()).is_err());
        }
        let malformed = "C:\\directory\0folder\\name\0\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        assert!(parse_open_dialog(&malformed).is_err());
        let relative = "C:\0file\0\0".encode_utf16().collect::<Vec<_>>();
        assert!(parse_open_dialog(&relative).is_err());
    }

    #[test]
    fn selection_limits_count_paths_and_utf8_bytes() {
        let mut paths = Paths::default();
        for _ in 0..MAX_PATHS {
            paths.push("C:\\x".into()).unwrap();
        }
        assert_eq!(
            paths.push("C:\\x".into()),
            Err(Error("picker_selection_limit"))
        );
        let mut paths = Paths::default();
        paths
            .push(format!("C:\\{}", "é".repeat((MAX_BYTES - 3) / 2)))
            .unwrap();
        assert_eq!(
            paths.push("C:\\x".into()),
            Err(Error("picker_selection_limit"))
        );
    }
}
