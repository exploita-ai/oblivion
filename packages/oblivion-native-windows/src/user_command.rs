//! Register only this process user's verified installed release in HKCU PATH.
//! Callers supply authenticated installation IDs, never a user SID or path.
//! The protected executable is launched directly; no shell forwards agent argv.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const PATH_LIMIT: usize = 65534;
const RECORD_LIMIT: usize = 8192;

pub struct Change {
    pub changed: bool,
    pub reopen_terminal: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct Value {
    kind: u32,
    bytes: Vec<u8>,
}

impl Value {
    fn units(&self) -> Result<Vec<u16>> {
        if !matches!(self.kind, REG_SZ | REG_EXPAND_SZ)
            || self.bytes.len() > PATH_LIMIT
            || self.bytes.len() < 2
            || self.bytes.len() % 2 != 0
        {
            return Err(Error("user_command_path_value_unsupported"));
        }
        let mut units: Vec<_> = self
            .bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        if units.pop() != Some(0) || units.contains(&0) {
            return Err(Error("user_command_path_value_unsupported"));
        }
        Ok(units)
    }

    fn string(kind: u32, units: &[u16]) -> Result<Self> {
        let value = Self {
            kind,
            bytes: units
                .iter()
                .copied()
                .chain(Some(0))
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        value.units()?;
        Ok(value)
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    directory: String,
    created_value: bool,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    kind: Option<u32>,
    sha256: String,
}

impl Snapshot {
    fn of(value: &Option<Value>) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"oblivion-user-path-v1\0");
        if let Some(value) = value {
            hash.update([1]);
            hash.update(value.kind.to_le_bytes());
            hash.update(&value.bytes);
        } else {
            hash.update([0]);
        }
        Self {
            kind: value.as_ref().map(|value| value.kind),
            sha256: format!("{:x}", hash.finalize()),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    desired: Option<Entry>,
    before: Snapshot,
    after: Snapshot,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    runtime_id: String,
    current: Option<Entry>,
    pending: Option<Pending>,
}

struct Scope {
    runtime_id: String,
    releases: String,
}

impl Scope {
    fn new(root: &str, runtime_id: &str) -> Result<Self> {
        if !oblivion_wire::control::valid_id(runtime_id)
            || runtime_id.bytes().all(|byte| byte == b'0')
            || root.contains([';', '"', '\0'])
            || root.len() > 1024
        {
            return Err(Error("invalid_user_command_binding"));
        }
        Ok(Self {
            runtime_id: runtime_id.into(),
            releases: format!(r"{root}\releases\"),
        })
    }

    fn directory(&self, bundle_id: &str) -> Result<String> {
        if !oblivion_bundle::hash(bundle_id) {
            return Err(Error("invalid_user_command_binding"));
        }
        Ok(format!(r"{}{bundle_id}\bin", self.releases))
    }

    fn owns(&self, entry: &Entry) -> bool {
        entry
            .directory
            .strip_prefix(&self.releases)
            .and_then(|path| path.strip_suffix(r"\bin"))
            .is_some_and(oblivion_bundle::hash)
    }

    fn decode(&self, value: &Value) -> Result<Record> {
        if value.kind != REG_SZ || value.bytes.len() > RECORD_LIMIT {
            return Err(Error("user_command_registration_unknown"));
        }
        let units = value
            .units()
            .map_err(|_| Error("user_command_registration_unknown"))?;
        let text =
            String::from_utf16(&units).map_err(|_| Error("user_command_registration_unknown"))?;
        let record: Record =
            serde_json::from_str(&text).map_err(|_| Error("user_command_registration_unknown"))?;
        if record.version != 1
            || record.runtime_id != self.runtime_id
            || record
                .current
                .as_ref()
                .is_some_and(|entry| !self.owns(entry))
            || record.current.is_none() && record.pending.is_none()
        {
            return Err(Error("user_command_registration_unknown"));
        }
        if let Some(pending) = &record.pending {
            if pending
                .desired
                .as_ref()
                .is_some_and(|entry| !self.owns(entry))
                || record.current.is_none() && pending.desired.is_none()
                || pending.before == pending.after
                || [&pending.before, &pending.after].iter().any(|snapshot| {
                    !oblivion_bundle::hash(&snapshot.sha256)
                        || snapshot
                            .kind
                            .is_some_and(|kind| !matches!(kind, REG_SZ | REG_EXPAND_SZ))
                })
            {
                return Err(Error("user_command_registration_unknown"));
            }
        }
        Ok(record)
    }
}

fn record_value(record: &Record) -> Result<Value> {
    let text =
        serde_json::to_string(record).map_err(|_| Error("user_command_registration_failed"))?;
    let value = Value::string(REG_SZ, &text.encode_utf16().collect::<Vec<_>>())?;
    if value.bytes.len() > RECORD_LIMIT {
        return Err(Error("user_command_registration_limit"));
    }
    Ok(value)
}

fn path_token(token: &[u16]) -> Vec<u16> {
    let token = if token.len() >= 2
        && token.first() == Some(&(b'"' as u16))
        && token.last() == Some(&(b'"' as u16))
    {
        &token[1..token.len() - 1]
    } else {
        token
    };
    let mut token: Vec<_> = token
        .iter()
        .map(|unit| {
            if *unit == b'/' as u16 {
                b'\\' as u16
            } else {
                *unit
            }
        })
        .collect();
    while token.len() > 3 && token.last() == Some(&(b'\\' as u16)) {
        token.pop();
    }
    token
}

trait Registry {
    fn path(&self) -> Result<Option<Value>>;
    fn record(&self) -> Result<Option<Value>>;
    fn set_path(&mut self, value: &Option<Value>) -> Result<()>;
    fn set_record(&mut self, value: &Option<Value>) -> Result<()>;
    fn matches(&self, token: &[u16], directory: &[u16], kind: u32) -> Result<bool>;
}

struct Plan {
    path: Option<Value>,
    entry: Option<Entry>,
}

fn plan(
    registry: &impl Registry,
    path: &Option<Value>,
    current: &Option<Entry>,
    desired: Option<&str>,
) -> Result<Option<Plan>> {
    let units = path.as_ref().map(Value::units).transpose()?;
    let mut tokens: Vec<Vec<u16>> = units
        .as_ref()
        .map(|units| {
            units
                .split(|unit| *unit == b';' as u16)
                .map(<[u16]>::to_vec)
                .collect()
        })
        .unwrap_or_default();
    if let Some(entry) = current {
        let directory: Vec<_> = entry.directory.encode_utf16().collect();
        let found: Vec<_> = tokens
            .iter()
            .enumerate()
            .filter(|(_, token)| **token == directory)
            .map(|(index, _)| index)
            .collect();
        if found.len() != 1 {
            return Err(Error("user_command_owned_entry_changed"));
        }
        if desired == Some(entry.directory.as_str()) {
            return Ok(None);
        }
        tokens.remove(found[0]);
    } else if desired.is_none() {
        return Ok(None);
    }
    let kind = path.as_ref().map_or(REG_EXPAND_SZ, |value| value.kind);
    let created_value = current
        .as_ref()
        .map_or(path.is_none(), |entry| entry.created_value);
    let entry = if let Some(desired) = desired {
        let directory: Vec<_> = desired.encode_utf16().collect();
        for token in &tokens {
            if registry.matches(token, &directory, kind)? {
                return Err(Error("user_command_path_collision"));
            }
        }
        tokens.push(directory);
        Some(Entry {
            directory: desired.into(),
            created_value,
        })
    } else {
        None
    };
    let path = if tokens.is_empty() && created_value {
        None
    } else {
        let units: Vec<_> = tokens
            .iter()
            .enumerate()
            .flat_map(|(index, token)| {
                (index > 0)
                    .then_some(b';' as u16)
                    .into_iter()
                    .chain(token.iter().copied())
            })
            .collect();
        Some(Value::string(kind, &units)?)
    };
    Ok(Some(Plan { path, entry }))
}

fn finish(registry: &mut impl Registry, record: &mut Record, desired: Option<Entry>) -> Result<()> {
    record.current = desired;
    record.pending = None;
    let value = record
        .current
        .as_ref()
        .map(|_| record_value(record))
        .transpose()?;
    registry.set_record(&value)
}

fn apply(registry: &mut impl Registry, scope: &Scope, desired: Option<&str>) -> Result<Change> {
    let mut changed = false;
    let mut record = registry
        .record()?
        .map(|value| scope.decode(&value))
        .transpose()?
        .unwrap_or(Record {
            version: 1,
            runtime_id: scope.runtime_id.clone(),
            current: None,
            pending: None,
        });
    if let Some(pending) = record.pending.clone() {
        let path = registry.path()?;
        let observed = Snapshot::of(&path);
        if observed == pending.before {
            let prepared = plan(
                registry,
                &path,
                &record.current,
                pending
                    .desired
                    .as_ref()
                    .map(|entry| entry.directory.as_str()),
            )?
            .ok_or(Error("user_command_registration_unknown"))?;
            if Snapshot::of(&prepared.path) != pending.after || prepared.entry != pending.desired {
                return Err(Error("user_command_registration_unknown"));
            }
            if Snapshot::of(&registry.path()?) != pending.before {
                return Err(Error("user_command_path_changed_during_registration"));
            }
            registry.set_path(&prepared.path)?;
        } else if observed != pending.after {
            return Err(Error("user_command_path_changed_during_registration"));
        }
        finish(registry, &mut record, pending.desired)?;
        changed = true;
    }
    let path = registry.path()?;
    let Some(prepared) = plan(registry, &path, &record.current, desired)? else {
        return Ok(Change {
            changed,
            reopen_terminal: desired.is_some() || changed,
        });
    };
    record.pending = Some(Pending {
        desired: prepared.entry.clone(),
        before: Snapshot::of(&path),
        after: Snapshot::of(&prepared.path),
    });
    // Ownership is durable before PATH changes. A failed write can be retried
    // only against these exact before/after snapshots; unrelated edits survive.
    registry.set_record(&Some(record_value(&record)?))?;
    if Snapshot::of(&registry.path()?) != Snapshot::of(&path) {
        return Err(Error("user_command_path_changed_during_registration"));
    }
    registry.set_path(&prepared.path)?;
    finish(registry, &mut record, prepared.entry)?;
    Ok(Change {
        changed: true,
        reopen_terminal: true,
    })
}

#[cfg(windows)]
mod native {
    use super::{Change, PATH_LIMIT, RECORD_LIMIT, Registry, Scope, Value, apply, path_token};
    use crate::installation::Root;
    use crate::security::Identity;
    use crate::{Error, Result};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA};
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
    use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_USERS, KEY_QUERY_VALUE, KEY_SET_VALUE,
        REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegFlushKey,
        RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
    };

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    impl Key {
        fn read_only(parent: HKEY, path: &str) -> Result<Option<Self>> {
            let mut key = null_mut();
            match unsafe {
                RegOpenKeyExW(parent, wide(path).as_ptr(), 0, KEY_QUERY_VALUE, &mut key)
            } {
                0 => Ok(Some(Self(key))),
                ERROR_FILE_NOT_FOUND => Ok(None),
                _ => Err(Error("user_command_registry_unavailable")),
            }
        }

        fn open(parent: HKEY, path: &str) -> Result<Self> {
            let mut key = null_mut();
            if unsafe {
                RegCreateKeyExW(
                    parent,
                    wide(path).as_ptr(),
                    0,
                    null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_QUERY_VALUE | KEY_SET_VALUE,
                    null(),
                    &mut key,
                    null_mut(),
                )
            } != 0
            {
                return Err(Error("user_command_registry_unavailable"));
            }
            Ok(Self(key))
        }
        fn get(&self, name: &str, maximum: usize) -> Result<Option<Value>> {
            let name = wide(name);
            let mut kind = 0;
            let mut length = 0;
            let status = unsafe {
                RegQueryValueExW(
                    self.0,
                    name.as_ptr(),
                    null(),
                    &mut kind,
                    null_mut(),
                    &mut length,
                )
            };
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if status != 0 || length as usize > maximum {
                return Err(Error("user_command_registry_value_unsupported"));
            }
            let mut bytes = vec![0; length as usize];
            let status = unsafe {
                RegQueryValueExW(
                    self.0,
                    name.as_ptr(),
                    null(),
                    &mut kind,
                    bytes.as_mut_ptr(),
                    &mut length,
                )
            };
            if status == ERROR_MORE_DATA {
                return Err(Error("user_command_registry_changed"));
            }
            if status != 0 || length as usize != bytes.len() {
                return Err(Error("user_command_registry_unavailable"));
            }
            Ok(Some(Value { kind, bytes }))
        }
        fn set(&self, name: &str, value: &Option<Value>) -> Result<()> {
            let name = wide(name);
            let status = if let Some(value) = value {
                unsafe {
                    RegSetValueExW(
                        self.0,
                        name.as_ptr(),
                        0,
                        value.kind,
                        value.bytes.as_ptr(),
                        value.bytes.len() as u32,
                    )
                }
            } else {
                unsafe { RegDeleteValueW(self.0, name.as_ptr()) }
            };
            if status != 0 && !(value.is_none() && status == ERROR_FILE_NOT_FOUND) {
                return Err(Error("user_command_registry_write_failed"));
            }
            if unsafe { RegFlushKey(self.0) } != 0 {
                return Err(Error("user_command_registry_flush_failed"));
            }
            Ok(())
        }
    }

    struct UserRegistry {
        environment: Key,
        ownership: Key,
    }
    impl UserRegistry {
        fn current() -> Result<Self> {
            Ok(Self {
                environment: Key::open(HKEY_CURRENT_USER, "Environment")?,
                ownership: Key::open(HKEY_CURRENT_USER, r"Software\Oblivion\UserCommand")?,
            })
        }
    }
    impl Registry for UserRegistry {
        fn path(&self) -> Result<Option<Value>> {
            self.environment.get("Path", PATH_LIMIT)
        }
        fn record(&self) -> Result<Option<Value>> {
            self.ownership.get("Registration", RECORD_LIMIT)
        }
        fn set_path(&mut self, value: &Option<Value>) -> Result<()> {
            self.environment.set("Path", value)
        }
        fn set_record(&mut self, value: &Option<Value>) -> Result<()> {
            self.ownership.set("Registration", value)
        }
        fn matches(&self, token: &[u16], directory: &[u16], kind: u32) -> Result<bool> {
            same_directory(token, directory, kind)
        }
    }

    fn same_directory(token: &[u16], directory: &[u16], kind: u32) -> Result<bool> {
        let expanded;
        let token = if kind == super::REG_EXPAND_SZ {
            let input: Vec<_> = token.iter().copied().chain(Some(0)).collect();
            let length = unsafe { ExpandEnvironmentStringsW(input.as_ptr(), null_mut(), 0) };
            if length == 0 || length as usize > PATH_LIMIT / 2 {
                return Err(Error("user_command_path_expansion_failed"));
            }
            expanded = {
                let mut value = vec![0; length as usize];
                if unsafe { ExpandEnvironmentStringsW(input.as_ptr(), value.as_mut_ptr(), length) }
                    != length
                {
                    return Err(Error("user_command_path_expansion_failed"));
                }
                value.pop();
                value
            };
            expanded.as_slice()
        } else {
            token
        };
        let token = path_token(token);
        if token.is_empty() {
            return Ok(false);
        }
        let compared = unsafe {
            CompareStringOrdinal(
                token.as_ptr(),
                token.len() as i32,
                directory.as_ptr(),
                directory.len() as i32,
                1,
            )
        };
        if compared == 0 {
            return Err(Error("user_command_path_comparison_failed"));
        }
        Ok(compared == CSTR_EQUAL)
    }

    /// Installation has already authenticated these IDs in the original user
    /// parent. Even an explicitly elevated parent writes only its own HKCU.
    pub fn register(runtime_id: &str, bundle_id: &str) -> Result<Change> {
        let root = Root::current()?;
        let scope = Scope::new(
            root.path()
                .to_str()
                .ok_or(Error("unsupported_installation_path"))?,
            runtime_id,
        )?;
        let directory = scope.directory(bundle_id)?;
        let change = apply(&mut UserRegistry::current()?, &scope, Some(&directory))?;
        notify();
        Ok(change)
    }
    pub fn unregister(runtime_id: &str) -> Result<Change> {
        let root = Root::current()?;
        let scope = Scope::new(
            root.path()
                .to_str()
                .ok_or(Error("unsupported_installation_path"))?,
            runtime_id,
        )?;
        let change = apply(&mut UserRegistry::current()?, &scope, None)?;
        if change.changed {
            notify();
        }
        Ok(change)
    }

    /// An elevated installer can run as a different administrator. The
    /// original caller must reconcile their own PATH before reinstalling.
    pub(crate) fn require_retired_registration_cleared(client: &Identity) -> Result<()> {
        let user = Key::read_only(HKEY_USERS, client.sid())?
            .ok_or(Error("user_command_registry_unavailable"))?;
        if let Some(key) = Key::read_only(user.0, r"Software\Oblivion\UserCommand")? {
            if key.get("Registration", RECORD_LIMIT)?.is_some() {
                return Err(Error("atomic_path_cleanup_pending"));
            }
        }
        Ok(())
    }
    fn notify() {
        // Windows applies this timeout per recipient. It does not update the
        // invoking terminal's inherited environment; callers say to reopen it.
        let mut result = 0;
        unsafe {
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                wide("Environment").as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                2000,
                &mut result,
            );
        }
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    #[cfg(test)]
    mod tests {
        use super::{Key, UserRegistry, wide};
        use crate::Error;
        use crate::user_command::{REG_EXPAND_SZ, REG_SZ, Registry, Scope, Value, apply};
        use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RegDeleteTreeW};

        struct Fixture {
            registry: Option<UserRegistry>,
            prefix: String,
        }
        impl Fixture {
            fn new() -> Self {
                let mut random = [0; 16];
                getrandom::getrandom(&mut random).unwrap();
                let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
                let prefix = format!(r"Software\Oblivion\UserCommandTests\{suffix}");
                Self {
                    registry: Some(UserRegistry {
                        environment: Key::open(
                            HKEY_CURRENT_USER,
                            &format!(r"{prefix}\Environment"),
                        )
                        .unwrap(),
                        ownership: Key::open(HKEY_CURRENT_USER, &format!(r"{prefix}\Ownership"))
                            .unwrap(),
                    }),
                    prefix,
                }
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                drop(self.registry.take());
                unsafe {
                    RegDeleteTreeW(HKEY_CURRENT_USER, wide(&self.prefix).as_ptr());
                }
            }
        }
        fn value(kind: u32, text: &str) -> Value {
            Value::string(kind, &text.encode_utf16().collect::<Vec<_>>()).unwrap()
        }

        #[test]
        fn isolated_hkcu_registration_preserves_other_values_and_unknown_collisions() {
            // The production adapter is used against fresh test-only keys.
            // No handle to the actual HKCU Environment/PATH is ever opened.
            let mut fixture = Fixture::new();
            let store = fixture.registry.as_mut().unwrap();
            let scope =
                Scope::new(r"C:\ProgramData\Oblivion\S-1-5-21-123", &"1".repeat(32)).unwrap();
            let a = scope.directory(&"a".repeat(64)).unwrap();
            let b = scope.directory(&"b".repeat(64)).unwrap();
            let original = value(
                REG_EXPAND_SZ,
                r"%SystemRoot%\System32;C:\Work & Code\ユニコード;",
            );
            store.set_path(&Some(original.clone())).unwrap();
            assert!(apply(store, &scope, Some(&a)).unwrap().changed);
            assert!(apply(store, &scope, Some(&b)).unwrap().changed);
            assert!(apply(store, &scope, None).unwrap().changed);
            assert!(store.path().unwrap() == Some(original));
            assert!(store.record().unwrap().is_none());
            let collision = value(
                REG_SZ,
                &format!("\"{}\\\"", a.to_lowercase().replace('\\', "/")),
            );
            store.set_path(&Some(collision.clone())).unwrap();
            assert!(matches!(
                apply(store, &scope, Some(&a)),
                Err(Error("user_command_path_collision"))
            ));
            assert!(store.path().unwrap().as_ref() == Some(&collision));
            assert!(store.record().unwrap().is_none());
            store
                .set_record(&Some(value(REG_SZ, "unknown registration")))
                .unwrap();
            assert!(matches!(
                apply(store, &scope, Some(&a)),
                Err(Error("user_command_registration_unknown"))
            ));
            assert!(store.path().unwrap().as_ref() == Some(&collision));
        }
    }
}

#[cfg(windows)]
pub(crate) use native::require_retired_registration_cleared;
#[cfg(windows)]
pub use native::{register, unregister};

#[cfg(test)]
mod tests {
    use super::{REG_EXPAND_SZ, REG_SZ, Record, Registry, Scope, Value, apply, path_token};
    use crate::{Error, Result};

    #[derive(Default)]
    struct Memory {
        path: Option<Value>,
        record: Option<Value>,
        fail_path: bool,
        fail_finish: bool,
        change_after_pending: bool,
    }
    impl Registry for Memory {
        fn path(&self) -> Result<Option<Value>> {
            Ok(self.path.clone())
        }
        fn record(&self) -> Result<Option<Value>> {
            Ok(self.record.clone())
        }
        fn set_path(&mut self, value: &Option<Value>) -> Result<()> {
            if self.fail_path {
                self.fail_path = false;
                return Err(Error("fixture_path_write_failed"));
            }
            self.path = value.clone();
            Ok(())
        }
        fn set_record(&mut self, value: &Option<Value>) -> Result<()> {
            if self.fail_finish
                && value.as_ref().is_some_and(|value| {
                    let text = String::from_utf16(&value.units().unwrap()).unwrap();
                    serde_json::from_str::<Record>(&text)
                        .unwrap()
                        .pending
                        .is_none()
                })
            {
                self.fail_finish = false;
                return Err(Error("fixture_finish_failed"));
            }
            self.record = value.clone();
            if self.change_after_pending {
                self.change_after_pending = false;
                self.path = Some(super::tests::value(REG_SZ, r"C:\ConcurrentInstaller"));
            }
            Ok(())
        }
        fn matches(&self, token: &[u16], directory: &[u16], _kind: u32) -> Result<bool> {
            Ok(path_token(token)
                .iter()
                .map(|unit| {
                    if (b'A' as u16..=b'Z' as u16).contains(unit) {
                        unit + 32
                    } else {
                        *unit
                    }
                })
                .eq(directory.iter().map(|unit| {
                    if (b'A' as u16..=b'Z' as u16).contains(unit) {
                        unit + 32
                    } else {
                        *unit
                    }
                })))
        }
    }
    fn scope() -> Scope {
        Scope::new(r"C:\ProgramData\Oblivion\S-1-5-21-123", &"1".repeat(32)).unwrap()
    }
    fn value(kind: u32, text: &str) -> Value {
        Value::string(kind, &text.encode_utf16().collect::<Vec<_>>()).unwrap()
    }
    fn error<T>(result: Result<T>, expected: &str) {
        assert!(matches!(result, Err(Error(code)) if code == expected));
    }

    #[test]
    fn exact_other_tokens_and_value_type_survive_install_update_and_uninstall() {
        for kind in [REG_SZ, REG_EXPAND_SZ] {
            let scope = scope();
            let a = scope.directory(&"a".repeat(64)).unwrap();
            let b = scope.directory(&"b".repeat(64)).unwrap();
            let mut units: Vec<_> = r"%SystemRoot%\System32;C:\Work & Code\ユニコード;"
                .encode_utf16()
                .collect();
            units.push(0xd800); // A non-owned raw UTF-16 token is never rewritten.
            let original = Value::string(kind, &units).unwrap();
            let mut store = Memory {
                path: Some(original.clone()),
                ..Memory::default()
            };
            assert!(apply(&mut store, &scope, Some(&a)).unwrap().changed);
            let mut expected = units.clone();
            expected.push(b';' as u16);
            expected.extend(a.encode_utf16());
            assert!(
                store.path.as_ref().unwrap().bytes == Value::string(kind, &expected).unwrap().bytes
            );
            assert!(!apply(&mut store, &scope, Some(&a)).unwrap().changed);
            assert!(apply(&mut store, &scope, Some(&b)).unwrap().changed);
            assert!(apply(&mut store, &scope, None).unwrap().changed);
            assert!(store.path == Some(original));
            assert!(store.record.is_none());
        }
    }

    #[test]
    fn absent_and_empty_path_values_are_restored_without_adopting_collision() {
        let scope = scope();
        let target = scope.directory(&"a".repeat(64)).unwrap();
        for original in [
            None,
            Some(value(REG_SZ, "")),
            Some(value(REG_EXPAND_SZ, ";")),
        ] {
            let mut store = Memory {
                path: original.clone(),
                ..Memory::default()
            };
            apply(&mut store, &scope, Some(&target)).unwrap();
            apply(&mut store, &scope, None).unwrap();
            assert!(store.path == original);
        }
        for token in [
            target.clone(),
            format!("\"{}\\\"", target.to_lowercase().replace('\\', "/")),
        ] {
            let original = value(REG_SZ, &format!(r"C:\Keep;{token}"));
            let mut store = Memory {
                path: Some(original.clone()),
                ..Memory::default()
            };
            error(
                apply(&mut store, &scope, Some(&target)),
                "user_command_path_collision",
            );
            assert!(store.path == Some(original));
            assert!(store.record.is_none());
        }
    }

    #[test]
    fn pending_before_and_after_writes_reconcile_only_known_snapshots() {
        for after in [false, true] {
            let scope = scope();
            let a = scope.directory(&"a".repeat(64)).unwrap();
            let b = scope.directory(&"b".repeat(64)).unwrap();
            let original = value(REG_EXPAND_SZ, r"%USERPROFILE%\tools");
            let mut store = Memory {
                path: Some(original.clone()),
                ..Memory::default()
            };
            apply(&mut store, &scope, Some(&a)).unwrap();
            store.fail_path = !after;
            store.fail_finish = after;
            assert!(apply(&mut store, &scope, Some(&b)).is_err());
            let pending = scope.decode(store.record.as_ref().unwrap()).unwrap();
            assert!(pending.pending.is_some());
            let change = apply(&mut store, &scope, Some(&b)).unwrap();
            assert!(change.changed && change.reopen_terminal);
            assert!(
                scope
                    .decode(store.record.as_ref().unwrap())
                    .unwrap()
                    .pending
                    .is_none()
            );
            apply(&mut store, &scope, None).unwrap();
            assert!(store.path == Some(original));
        }
    }

    #[test]
    fn unrelated_changes_unknown_records_and_duplicate_owned_tokens_are_preserved() {
        let scope = scope();
        let target = scope.directory(&"a".repeat(64)).unwrap();
        let original = value(REG_SZ, r"C:\Keep");
        let mut store = Memory {
            path: Some(original.clone()),
            fail_path: true,
            ..Memory::default()
        };
        assert!(apply(&mut store, &scope, Some(&target)).is_err());
        store.path = Some(value(REG_SZ, r"C:\OtherInstaller;C:\Keep"));
        let path = store.path.clone();
        let record = store.record.clone();
        error(
            apply(&mut store, &scope, Some(&target)),
            "user_command_path_changed_during_registration",
        );
        assert!(store.path == path && store.record == record);
        for unknown in [
            value(REG_SZ, "{}"),
            value(2, "{}"),
            value(REG_SZ, r#"{"version":0,"runtime_id":"canary"}"#),
        ] {
            store.record = Some(unknown.clone());
            error(
                apply(&mut store, &scope, Some(&target)),
                "user_command_registration_unknown",
            );
            assert!(store.path == path && store.record == Some(unknown));
        }
        store = Memory {
            path: Some(original),
            ..Memory::default()
        };
        apply(&mut store, &scope, Some(&target)).unwrap();
        store.path = Some(value(REG_SZ, &format!(r"C:\Keep;{target};{target}")));
        let path = store.path.clone();
        error(
            apply(&mut store, &scope, None),
            "user_command_owned_entry_changed",
        );
        assert!(store.path == path);
        store = Memory {
            path: Some(Value {
                kind: 3,
                bytes: vec![1, 2],
            }),
            ..Memory::default()
        };
        error(
            apply(&mut store, &scope, Some(&target)),
            "user_command_path_value_unsupported",
        );
        assert!(store.record.is_none());
    }

    #[test]
    fn change_during_pending_flush_is_not_overwritten() {
        let scope = scope();
        let target = scope.directory(&"a".repeat(64)).unwrap();
        let mut store = Memory {
            path: Some(value(REG_SZ, r"C:\Keep")),
            change_after_pending: true,
            ..Memory::default()
        };
        error(
            apply(&mut store, &scope, Some(&target)),
            "user_command_path_changed_during_registration",
        );
        assert!(store.path == Some(value(REG_SZ, r"C:\ConcurrentInstaller")));
        assert!(
            scope
                .decode(store.record.as_ref().unwrap())
                .unwrap()
                .pending
                .is_some()
        );
    }
}
