use oblivion_host::{egress, keys, network, persistence, settings, transfers};
use oblivion_transport::policy::{Policy, Session, Tools};
use oblivion_transport::provider::Provider;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

const GENERAL: &str = "/dev/mapper/oblivion-general";
const SESSION: &str = "/dev/mapper/oblivion-session";
const RUN: &str = "/run/oblivion";
const RECOVERY: &str = "/run/oblivion/recovery-required";
const MOUNT: &str = "/run/oblivion/general";
const PROFILE: &str = "/run/oblivion/general/profile";
const EPHEMERAL: &str = "/run/oblivion/ephemeral.luks";
const MIB: u64 = 1024 * 1024;

pub struct Error(pub &'static str);
pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    general_image: PathBuf,
    general_mib: u64,
    session_mib: u64,
    pbkdf_memory_kib: u32,
    manager_uid: u32,
    vm: Option<crate::vm::Config>,
    gateway: Option<crate::vm::Config>,
    import: Option<crate::vm::Config>,
    export: Option<crate::vm::Config>,
    onion: Option<crate::onion_host::Config>,
    #[serde(default)]
    gateway_network: bool,
    #[serde(default)]
    usb_persistence: bool,
    #[serde(default)]
    network_profiles: bool,
    #[serde(skip)]
    usb: Option<crate::usb::Inspection>,
}

#[derive(Serialize)]
struct Status {
    general_present: bool,
    general_incomplete: bool,
    general_open: bool,
    general_mounted: bool,
    general_readonly: bool,
    session_open: bool,
    session_mode: Option<String>,
    active_session: Option<String>,
    sessions: Vec<String>,
    session_titles: std::collections::BTreeMap<String, String>,
    incomplete_sessions: Vec<String>,
    available_bytes: Option<u64>,
    session_bytes: u64,
    vm_state: Option<String>,
    laboratory_emulation: bool,
    recovery_required: bool,
    api_key_present: Option<bool>,
    api_keys: Option<keys::Status>,
    egress: Option<egress::Status>,
    network_policy: Option<network::Status>,
    gateway_state: Option<String>,
    gateway_vm_state: Option<String>,
    gateway_network: bool,
    transfers_configured: bool,
    persistence: Option<persistence::Status>,
    network_profiles_saved: Option<bool>,
    settings: settings::Status,
    network_status: network::Observation,
    connections: Option<oblivion_host::connections::Snapshot>,
    system: crate::system_info::Status,
    debug_available: bool,
}

pub fn main() -> Result<()> {
    secure_process()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    require(args.len() >= 3 && args[0] == "--config", "usage")?;
    let config = Config::read(Path::new(&args[1]))?;
    if args.len() == 3 && args[2] == "serve" {
        return crate::ipc::serve(Path::new(&args[1]), config.manager_uid);
    }
    let op = args[2].as_str();
    if args.len() == 3 && op == "debug" {
        return crate::debug::run(&password(false)?);
    }
    // The worker's stop hook runs while the controller may hold storage.lock
    // waiting for systemd stop. It must not reacquire that lock and deadlock.
    if args.len() == 3 && op == "transfer-cleanup" {
        return crate::transfer_host::cleanup();
    }
    if args.len() == 3 && op == "onion-cleanup" {
        return crate::onion_host::cleanup();
    }
    if args.len() == 3 && op == "onion-host-run" {
        require(
            !recovery_required()? && mount_mode()? != MountMode::Closed,
            "general_not_open",
        )?;
        return crate::onion_host::serve(
            config.onion.as_ref().ok_or(Error("onion_not_configured"))?,
            config.manager_uid,
        );
    }
    if args.len() == 3 && op == "transfer-host-run" {
        require(
            !recovery_required()?
                && (crate::transfer_host::archiving()?
                    || mapping_open("oblivion-session")? && !crate::vm::stopped()?),
            "session_not_open",
        )?;
        return crate::transfer_host::serve(
            config.import.as_ref(),
            config.export.as_ref(),
            config.manager_uid,
        );
    }
    if args.len() == 3 && op == "gateway-host-run" {
        require(!recovery_required()?, "recovery_required")?;
        require(mount_mode()? != MountMode::Closed, "general_not_open")?;
        let gateway = config
            .gateway
            .as_ref()
            .ok_or(Error("gateway_not_configured"))?;
        let (saved, selected) = transport_profiles()?;
        return crate::gateway::serve(
            gateway,
            read_api_key()?,
            selected.unwrap_or(saved).into_transport(),
            config.gateway_network,
        );
    }
    require(
        args.len()
            == if matches!(
                op,
                "open" | "enter" | "enter-documents" | "discard-session-pending"
            ) {
                4
            } else {
                3
            },
        "usage",
    )?;
    // Latch before taking the operation lock: a worker may still be completing
    // when the manager dies. Its completion must not permit another opening.
    if matches!(op, "lock" | "recover") {
        runtime()?;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(RECOVERY)
            .map_err(|_| Error("recovery_marker_failed"))?;
    }
    let _lock = lock()?;
    // A broken transfer record must not prevent teardown from revoking the
    // current grant. Admission guards apply to new work, not close/recovery.
    if !matches!(
        op,
        "status" | "transfers" | "onion" | "close" | "leave" | "force-leave" | "lock" | "recover"
    ) {
        require(
            !crate::transfer_host::archiving()? && !crate::onion_host::archiving()?,
            "backup_active",
        )?;
    }
    if matches!(
        op,
        "init-general"
            | "prepare-usb"
            | "save-network"
            | "unlock"
            | "unlock-ephemeral"
            | "create"
            | "rename-session"
            | "open"
            | "enter"
            | "enter-ephemeral"
            | "enter-documents"
            | "enter-documents-ephemeral"
            | "start-chat"
            | "chat-ready"
            | "discard-general-pending"
            | "discard-session-pending"
            | "set-api-key"
            | "clear-api-key"
            | "api-keys"
            | "egress"
            | "network-policy"
            | "settings"
            | "connections"
    ) {
        require(!recovery_required()?, "recovery_required")?;
    }
    match op {
        "onion" => {
            let mut payload = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(4097)
                .read_to_end(&mut payload)
                .map_err(|_| Error("invalid_onion_request"))?;
            require(payload.len() <= 4096, "invalid_onion_request")?;
            let command: oblivion_host::onion::Command =
                serde_json::from_slice(&payload).map_err(|_| Error("invalid_onion_request"))?;
            command.validate().map_err(Error)?;
            let status = match command {
                oblivion_host::onion::Command::Status {} => {
                    crate::onion_host::status(config.onion.is_some())?
                }
                oblivion_host::onion::Command::Receive { client_auth } => {
                    require(
                        config.onion.is_some()
                            && !recovery_required()?
                            && mount_mode()? != MountMode::Closed,
                        "general_not_open",
                    )?;
                    crate::onion_host::receive(client_auth)?
                }
                oblivion_host::onion::Command::Access {} => {
                    let access = crate::onion_host::access()?;
                    println!(
                        "{}",
                        serde_json::to_string(&access).map_err(|_| Error("encode_failed"))?
                    );
                    return Ok(());
                }
                oblivion_host::onion::Command::Freeze {} => crate::onion_host::freeze()?,
                oblivion_host::onion::Command::Import {} => crate::onion_host::import()?,
                oblivion_host::onion::Command::Stage {} => crate::onion_host::stage()?,
                oblivion_host::onion::Command::Share { client_auth } => {
                    crate::onion_host::share(client_auth)?
                }
                oblivion_host::onion::Command::Cancel {} => {
                    let _checkpoint = crate::onion_host::shutdown()?;
                    oblivion_host::onion::Status::closed(config.onion.is_some())
                }
                oblivion_host::onion::Command::PrepareBackup {
                    id,
                    password,
                    ttl_seconds,
                } => {
                    require(config.onion.is_some(), "onion_not_configured")?;
                    require(
                        !crate::onion_host::prepared()? && !crate::transfer_host::prepared()?,
                        "transfer_active",
                    )?;
                    config.prepare_backup(&id, password.as_bytes())?;
                    crate::onion_host::start(id, ttl_seconds, true)?
                }
                oblivion_host::onion::Command::Prepare { ttl_seconds } => {
                    require(config.onion.is_some(), "onion_not_configured")?;
                    require(
                        !recovery_required()? && mount_mode()? != MountMode::Closed,
                        "general_not_open",
                    )?;
                    let (id, mode) = session_info()?.ok_or(Error("session_not_open"))?;
                    require(
                        matches!(mode.as_str(), "documents" | "chat") && !crate::vm::stopped()?,
                        "session_not_open",
                    )?;
                    crate::onion_host::start(id, ttl_seconds, false)?
                }
            };
            println!(
                "{}",
                serde_json::to_string(&status).map_err(|_| Error("encode_failed"))?
            );
            Ok(())
        }
        "init-general" => {
            require(!config.usb_persistence, "usb_confirmation_required")?;
            config.initialize(&password(true)?)
        }
        "prepare-usb" => {
            require(config.usb_persistence, "usb_not_configured")?;
            require(
                !mapping_open("oblivion-general")?
                    && !mapping_open("oblivion-session")?
                    && mount_mode()? == MountMode::Closed,
                "volume_busy",
            )?;
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("secret_read_failed"))?;
            require(bytes.len() <= 4096, "invalid_secret_length")?;
            let request: persistence::Prepare =
                serde_json::from_slice(&bytes).map_err(|_| Error("invalid_usb_request"))?;
            require(
                (16..=1024).contains(&request.password.len()),
                "invalid_secret_length",
            )?;
            let device = crate::usb::prepare(&request.plan, config.general_mib * MIB)?;
            config.format(&device, request.password.as_bytes())?;
            crypt_open(
                &device,
                "oblivion-general",
                request.password.as_bytes(),
                false,
            )?;
            let formatted = run(
                "/usr/sbin/mkfs.ext4",
                &[
                    "-q",
                    "-m",
                    "0",
                    "-E",
                    "lazy_itable_init=0,lazy_journal_init=0",
                    GENERAL,
                ],
                None,
            );
            let closed = crypt_close("oblivion-general");
            formatted?;
            closed?;
            crate::usb::publish(&request.plan, config.general_mib * MIB)
        }
        "discard-general-pending" => {
            if config.usb_persistence {
                require(
                    !mapping_open("oblivion-general")?
                        && !mapping_open("oblivion-session")?
                        && mount_mode()? == MountMode::Closed,
                    "volume_busy",
                )?;
                return crate::usb::discard(config.general_mib * MIB);
            }
            require(
                !config
                    .general_image
                    .try_exists()
                    .map_err(|_| Error("image_check_failed"))?,
                "general_already_exists",
            )?;
            require(
                !mapping_open("oblivion-general")? && mount_mode()? == MountMode::Closed,
                "volume_busy",
            )?;
            discard_pending(&config.pending_general())
        }
        "discard-session-pending" => {
            validate_id(&args[3])?;
            require(
                mount_mode()? == MountMode::ReadWrite,
                "general_not_writable",
            )?;
            discard_pending(&PathBuf::from(format!(
                "{MOUNT}/sessions/{}.pending",
                args[3]
            )))?;
            discard_restore_record(&args[3])
        }
        "unlock" | "unlock-ephemeral" => {
            config.unlock(&password(false)?, op == "unlock-ephemeral")?;
            crate::host_settings::restore()?;
            if config.network_profiles {
                crate::host_network::restore()?;
            }
            clear_key_selection()?;
            clear_key_file("api-keys.json")?;
            clear_key_file("api-key-default")?;
            clear_transport_selection()?;
            clear_network_selection()?;
            Ok(())
        }
        "create" => config.create(&password(true)?),
        "rename-session" => {
            let command: oblivion_host::session_title::Rename =
                serde_json::from_slice(&password(false)?)
                    .map_err(|_| Error("invalid_session_title"))?;
            validate_id(&command.id)?;
            oblivion_host::session_title::validate(&command.title).map_err(Error)?;
            let mode = mount_mode()?;
            require(mode != MountMode::Closed, "general_not_open")?;
            if mode == MountMode::ReadOnly {
                require(
                    session_info()?.is_some_and(|(id, _)| id == command.id),
                    "session_not_open",
                )?;
                return write_key_file("session-title", command.title.as_bytes());
            }
            trusted_file(&Path::new(MOUNT).join(format!("sessions/{}.luks", command.id)))?;
            write_session_title(&command.id, &command.title)
        }
        "settings-catalog" => {
            println!(
                "{}",
                serde_json::to_string(&crate::host_settings::catalog()?)
                    .map_err(|_| Error("encode_failed"))?
            );
            Ok(())
        }
        "claim-intro" => {
            runtime()?;
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(format!("{RUN}/intro-shown"))
            {
                Ok(_) => println!("true"),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    println!("false")
                }
                Err(_) => return Err(Error("intro_marker_failed")),
            }
            Ok(())
        }
        "enter-documents" | "enter-documents-ephemeral" => {
            let vm = config.vm.as_ref().ok_or(Error("vm_not_configured"))?;
            vm.validate()?;
            require(crate::vm::stopped()?, "vm_already_running")?;
            let id = if op == "enter-documents" {
                args[3].clone()
            } else {
                random_id()?
            };
            if op == "enter-documents" {
                config.open(&id, &password(false)?)?;
            } else {
                config.open_ephemeral()?;
            }
            write_session_info(&id, "starting")?;
            if let Err(error) = vm.start_documents() {
                crate::vm::stop(true)?;
                close_session()?;
                clear_key_file("session-info")?;
                return Err(error);
            }
            write_session_info(&id, "documents")
        }
        "start-chat" => {
            require(!crate::onion_host::prepared()?, "transfer_active")?;
            require(
                mapping_open("oblivion-session")?
                    && session_info()?.is_some_and(|(_, mode)| mode == "documents"),
                "documents_not_open",
            )?;
            require(!crate::transfer_host::prepared()?, "transfer_active")?;
            let id = session_info()?.ok_or(Error("session_not_open"))?.0;
            let vm = config.vm.as_ref().ok_or(Error("vm_not_configured"))?;
            require(api_key_present()?, "api_key_missing")?;
            config.start_gateway(false)?;
            require(crate::gateway::state()? == "active", "gateway_not_ready")?;
            crate::gateway::ready()?;
            let provider = selected_provider()?;
            let (saved, selected) = policy_profiles()?;
            let tools = selected
                .or(saved)
                .map(|policy| Session::new(&id).map(|session| Tools { session, policy }))
                .transpose()
                .map_err(Error)?;
            // Block credential edits throughout the transition, including partial startup.
            write_session_info(&id, "starting")?;
            let result = (|| {
                crate::vm::stop(false)?;
                let token = crate::gateway::prepare()?;
                vm.start(Some(&token), Some(provider), tools)
            })();
            if result.is_err() {
                recover_chat(&config)?;
                return result;
            }
            Ok(())
        }
        "chat-ready" => {
            require(
                mapping_open("oblivion-session")? && !crate::vm::stopped()?,
                "session_not_open",
            )?;
            let (id, mode) = session_info()?.ok_or(Error("session_not_open"))?;
            require(mode == "starting", "chat_not_starting")?;
            write_session_info(&id, "chat")
        }
        "chat-recover" => {
            require(!crate::onion_host::prepared()?, "transfer_active")?;
            recover_chat(&config)
        }
        "cancel-chat" => {
            let (_, mode) = session_info()?.ok_or(Error("session_not_open"))?;
            require(
                matches!(mode.as_str(), "starting" | "documents"),
                "chat_already_started",
            )?;
            if mode == "starting" {
                recover_chat(&config)?;
            }
            crate::gateway::shutdown()?;
            Ok(())
        }
        "browse" => {
            require(
                !recovery_required()?
                    && mapping_open("oblivion-session")?
                    && !crate::vm::stopped()?,
                "session_not_open",
            )?;
            let request: oblivion_transfer::browser::Request =
                serde_json::from_reader(std::io::stdin().take(4096))
                    .map_err(|_| Error("invalid_directory_request"))?;
            request
                .validate()
                .map_err(|_| Error("invalid_directory_request"))?;
            require(
                request.path.is_empty()
                    || matches!(
                        request.path.split('/').next(),
                        Some("workspace" | "imports")
                    ),
                "invalid_document_root",
            )?;
            let id = random_id()?;
            let result = (|| {
                use oblivion_transfer::endpoint::{read_message, write_message};
                let stream = crate::vm::copy_port(&id, true)?;
                let mut channel = oblivion_host::channel::Channel::new(
                    &stream,
                    std::time::Duration::from_secs(90),
                );
                let mut ready = [0; 6];
                channel
                    .read_exact(&mut ready)
                    .map_err(|_| Error("documents_not_ready"))?;
                require(&ready == b"ready\n", "invalid_transfer_guest")?;
                channel
                    .write_all(b"G")
                    .map_err(|_| Error("documents_not_ready"))?;
                write_message(&mut channel, &serde_json::json!({"browse": &request}))
                    .map_err(|_| Error("directory_request_failed"))?;
                let response: oblivion_transfer::browser::Response =
                    read_message(&mut channel, 64 * 1024)
                        .map_err(|_| Error("directory_read_failed"))?;
                let oblivion_transfer::browser::Response::Page(page) = response else {
                    return Err(Error("directory_unavailable"));
                };
                page.validate(&request)
                    .map_err(|_| Error("invalid_directory_page"))?;
                Ok(page)
            })();
            let cleanup = crate::vm::remove_copy_port(&id);
            let page = result?;
            cleanup?;
            println!(
                "{}",
                serde_json::to_string(&page).map_err(|_| Error("encode_failed"))?
            );
            Ok(())
        }
        "chat-export" => {
            let request: oblivion_host::chat_export::Request =
                serde_json::from_reader(std::io::stdin().take(4096))
                    .map_err(|_| Error("invalid_chat_export_request"))?;
            require(request.is_chat_export(), "invalid_chat_export_request")?;
            let response = session_export(request)?;
            println!(
                "{}",
                serde_json::to_string(&response).map_err(|_| Error("encode_failed"))?
            );
            Ok(())
        }
        "diagnostics" => {
            let request: oblivion_host::diagnostics::Request =
                serde_json::from_reader(std::io::stdin().take(1024))
                    .map_err(|_| Error("invalid_diagnostics_request"))?;
            let report = diagnostic_report()?;
            let output = match request {
                oblivion_host::diagnostics::Request::Preview => serde_json::to_string(&report),
                oblivion_host::diagnostics::Request::Export => serde_json::to_string(
                    &session_export(oblivion_host::chat_export::Request::Diagnostics { report })?,
                ),
            }
            .map_err(|_| Error("encode_failed"))?;
            println!("{output}");
            Ok(())
        }
        "network-menu" => Err(Error("network_manager_required")),
        "connections" => {
            require(mount_mode()? != MountMode::Closed, "general_not_open")?;
            require(credentials_editable()?, "session_must_be_closed")?;
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("invalid_network_request"))?;
            require(bytes.len() <= 4096, "invalid_network_request")?;
            let command =
                serde_json::from_slice(&bytes).map_err(|_| Error("invalid_network_request"))?;
            crate::host_network::change(
                command,
                config.network_profiles && mount_mode()? == MountMode::ReadWrite,
            )
        }
        "settings" => {
            require(
                !mapping_open("oblivion-session")? && crate::vm::stopped()?,
                "session_must_be_closed",
            )?;
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("settings_read_failed"))?;
            require(bytes.len() <= 4096, "invalid_settings")?;
            let command: settings::Command =
                serde_json::from_slice(&bytes).map_err(|_| Error("invalid_settings"))?;
            match command {
                settings::Command::Apply { preferences } => {
                    crate::host_settings::apply(&preferences)
                }
                settings::Command::Save { preferences } => {
                    require(
                        mount_mode()? == MountMode::ReadWrite,
                        "general_not_writable",
                    )?;
                    crate::host_settings::save(&preferences)
                }
            }
        }
        "save-network" => {
            require(config.network_profiles, "network_profiles_not_configured")?;
            require(
                mount_mode()? == MountMode::ReadWrite,
                "general_not_writable",
            )?;
            require(
                !mapping_open("oblivion-session")? && crate::vm::stopped()?,
                "session_must_be_closed",
            )?;
            crate::host_network::save()
        }
        "set-api-key" | "clear-api-key" => {
            require(
                mount_mode()? == MountMode::ReadWrite,
                "general_not_writable",
            )?;
            let status = read_keyring()?.status(key_selection()?);
            let command = if op == "clear-api-key" {
                status.selected.map(|id| keys::Command::Remove { id })
            } else {
                let bytes = password(false)?;
                let key = Zeroizing::new(
                    std::str::from_utf8(&bytes)
                        .map_err(|_| Error("invalid_api_key"))?
                        .to_owned(),
                );
                Some(if let Some(id) = status.selected {
                    keys::Command::Replace { id, key }
                } else {
                    require(status.entries.is_empty(), "api_key_missing")?;
                    keys::Command::Add {
                        provider: Provider::AbliterationAi,
                        name: "Predefinita".to_owned(),
                        key,
                    }
                })
            };
            require(
                !mapping_open("oblivion-session")? && crate::vm::stopped()?,
                "session_must_be_closed",
            )?;
            if let Some(command) = command {
                config.change_keys(command)?;
            }
            Ok(())
        }
        "api-keys" => {
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("secret_read_failed"))?;
            require(bytes.len() <= 4096, "invalid_secret_length")?;
            let command =
                serde_json::from_slice(&bytes).map_err(|_| Error("invalid_key_command"))?;
            config.change_keys(command)
        }
        "egress" => {
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(egress::LIMIT as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("secret_read_failed"))?;
            require(bytes.len() <= egress::LIMIT, "invalid_secret_length")?;
            let command =
                serde_json::from_slice(&bytes).map_err(|_| Error("invalid_transport_command"))?;
            config.change_transport(command)
        }
        "network-policy" => {
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("secret_read_failed"))?;
            require(bytes.len() <= 4096, "invalid_secret_length")?;
            let command =
                serde_json::from_slice(&bytes).map_err(|_| Error("invalid_network_command"))?;
            config.change_network_policy(command)
        }
        "transfers" => {
            let mut bytes = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| Error("transfer_request_failed"))?;
            require(bytes.len() <= 4096, "transfer_request_too_large")?;
            let command: transfers::Command =
                serde_json::from_slice(&bytes).map_err(|_| Error("invalid_transfer_request"))?;
            if !matches!(
                command,
                transfers::Command::List | transfers::Command::Cancel
            ) {
                require(!crate::onion_host::prepared()?, "transfer_active")?;
            }
            if !matches!(command, transfers::Command::Cancel) {
                require(
                    !recovery_required()? && mount_mode()? != MountMode::Closed,
                    "general_not_open",
                )?;
            }
            if matches!(
                command,
                transfers::Command::Import { .. }
                    | transfers::Command::Export { .. }
                    | transfers::Command::Recover
            ) {
                require(
                    !recovery_required()?
                        && mapping_open("oblivion-session")?
                        && !crate::vm::stopped()?,
                    "session_not_open",
                )?;
            }
            match command {
                transfers::Command::List => {
                    let status = crate::transfer_host::status(
                        config.import.is_some(),
                        config.export.is_some(),
                        &config.general_image,
                    )?;
                    println!(
                        "{}",
                        serde_json::to_string(&status).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
                transfers::Command::Import { source } => {
                    config
                        .import
                        .as_ref()
                        .ok_or(Error("transfers_not_configured"))?
                        .validate()?;
                    let started =
                        crate::transfer_host::start(&source, &config.general_image, false)?;
                    println!(
                        "{}",
                        serde_json::to_string(&started).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
                transfers::Command::Export { target } => {
                    config
                        .export
                        .as_ref()
                        .ok_or(Error("exports_not_configured"))?
                        .validate()?;
                    let started =
                        crate::transfer_host::start(&target, &config.general_image, true)?;
                    println!(
                        "{}",
                        serde_json::to_string(&started).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
                transfers::Command::Backup {
                    id,
                    target,
                    password,
                } => {
                    config
                        .export
                        .as_ref()
                        .ok_or(Error("exports_not_configured"))?
                        .validate()?;
                    crate::transfer_host::idle()?;
                    config.prepare_backup(&id, password.as_bytes())?;
                    drop(password);
                    let started =
                        crate::transfer_host::start_backup(&id, &target, &config.general_image)?;
                    println!(
                        "{}",
                        serde_json::to_string(&started).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
                transfers::Command::Restore { source } => {
                    config
                        .import
                        .as_ref()
                        .ok_or(Error("transfers_not_configured"))?
                        .validate()?;
                    let started =
                        crate::transfer_host::start_restore(&source, &config.general_image)?;
                    println!(
                        "{}",
                        serde_json::to_string(&started).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
                transfers::Command::RestoreFinish { id, password } => {
                    crate::transfer_host::idle()?;
                    config.finish_restore(&id, password.as_bytes())
                }
                transfers::Command::RestoreDiscard { id } => {
                    crate::transfer_host::idle()?;
                    closed_archive()?;
                    validate_id(&id)?;
                    let path = Path::new(MOUNT).join(format!("sessions/{id}.pending"));
                    if path
                        .try_exists()
                        .map_err(|_| Error("restore_record_failed"))?
                    {
                        discard_pending(&path)?;
                    }
                    discard_restore_record(&id)
                }
                transfers::Command::Recover => {
                    let started = crate::transfer_host::start_recovery()?;
                    println!(
                        "{}",
                        serde_json::to_string(&started).map_err(|_| Error("encode_failed"))?
                    );
                    Ok(())
                }
                transfers::Command::Cancel => crate::transfer_host::stop(),
            }
        }
        "open" => config.open(&args[3], &password(false)?),
        "enter" | "enter-ephemeral" => {
            let vm = config.vm.as_ref().ok_or(Error("vm_not_configured"))?;
            vm.validate()?;
            require(crate::vm::stopped()?, "vm_already_running")?;
            if config.gateway.is_some() {
                config.start_gateway(true)?;
                crate::gateway::ready()?;
            }
            let id = if op == "enter-ephemeral" {
                random_id()?
            } else {
                args[3].clone()
            };
            let tools = if config.gateway.is_some() {
                let (saved, selected) = policy_profiles()?;
                selected
                    .or(saved)
                    .map(|policy| Session::new(&id).map(|session| Tools { session, policy }))
                    .transpose()
                    .map_err(Error)?
            } else {
                None
            };
            if op == "enter-ephemeral" {
                config.open_ephemeral()?;
            } else {
                config.open(&id, &password(false)?)?;
            }
            write_session_info(&id, "chat")?;
            // Failed startup keeps the vault interlocked until explicit leave/lock.
            let result = (|| {
                let token = if config.gateway.is_some() {
                    Some(crate::gateway::prepare()?)
                } else {
                    None
                };
                let provider = if token.is_some() {
                    Some(selected_provider()?)
                } else {
                    None
                };
                vm.start(token.as_deref().map(String::as_str), provider, tools)
            })();
            if result.is_err() && config.gateway.is_some() {
                crate::gateway::revoke()?;
            }
            result
        }
        "close" | "leave" | "force-leave" => {
            // Transfer cleanup can fail while a session is still running.
            // Revoke its network before attempting any fallible teardown.
            let gateway = if config.gateway.is_some() {
                crate::gateway::revoke()
            } else {
                Ok(())
            };
            let onion = if config.onion.is_some() || crate::onion_host::prepared()? {
                crate::onion_host::shutdown()
            } else {
                Ok(true)
            };
            onion?;
            gateway?;
            if config.import.is_some()
                || config.export.is_some()
                || crate::transfer_host::prepared()?
            {
                match crate::transfer_host::stop() {
                    Err(_) if op == "force-leave" => {
                        // An unresponsive destination cannot acknowledge port
                        // removal. Only the explicit forced-close action may
                        // destroy it, then require cleanup again before LUKS.
                        crate::vm::stop(true)?;
                        crate::transfer_host::stop()?;
                    }
                    result => result?,
                }
            }
            if config.vm.is_some() && op != "close" {
                crate::vm::stop(op == "force-leave")?;
            }
            close_session()?;
            clear_key_selection()?;
            clear_key_file("session-info")
        }
        "lock" | "recover" => {
            // Attempt every independent shutdown before checking the results.
            // A failed checkpoint is not a running gateway; a failed stop is.
            // Never close mappings while a worker's stop is unconfirmed.
            let gateway = config
                .gateway
                .as_ref()
                .map_or(Ok(true), |_| crate::gateway::shutdown());
            let onion = if config.onion.is_some() || crate::onion_host::prepared()? {
                crate::onion_host::shutdown()
            } else {
                Ok(true)
            };
            let transfers = (|| {
                if config.import.is_some()
                    || config.export.is_some()
                    || crate::transfer_host::prepared()?
                {
                    crate::transfer_host::stop()?;
                }
                Ok(())
            })();
            let session = config
                .vm
                .as_ref()
                .map_or(Ok(()), |_| crate::vm::stop(false));
            let checkpoint = gateway?;
            let onion_checkpoint = onion?;
            transfers?;
            session?;
            close_general()?;
            clear_key_file("session-info")?;
            clear_key_selection()?;
            clear_key_file("api-keys.json")?;
            clear_key_file("api-key-default")?;
            clear_transport_selection()?;
            clear_network_selection()?;
            if recovery_required()? {
                fs::remove_file(RECOVERY).map_err(|_| Error("recovery_clear_failed"))?;
            }
            require(checkpoint && onion_checkpoint, "locked_without_tor_state")
        }
        "status" => {
            let mode = mount_mode()?;
            let api_keys = if mode == MountMode::Closed {
                None
            } else {
                Some(read_keyring()?.status(key_selection()?))
            };
            let status = Status {
                connections: crate::host_network::snapshot().ok(),
                system: crate::system_info::status(),
                debug_available: crate::debug::available(),
                network_status: network_observation(
                    session_info()?.as_ref().map(|(_, mode)| mode.as_str()),
                ),
                session_mode: session_info()?.map(|(_, mode)| mode),
                active_session: session_info()?.map(|(id, _)| id),
                settings: crate::host_settings::status(mode != MountMode::Closed)?,
                general_present: if let Some(usb) = &config.usb {
                    usb.status.present
                } else {
                    config
                        .general_image
                        .try_exists()
                        .map_err(|_| Error("image_check_failed"))?
                },
                general_incomplete: if let Some(usb) = &config.usb {
                    usb.status.incomplete
                } else {
                    config
                        .pending_general()
                        .try_exists()
                        .map_err(|_| Error("image_check_failed"))?
                },
                persistence: config.usb.as_ref().map(|usb| usb.status.clone()),
                network_profiles_saved: if config.network_profiles && mode != MountMode::Closed {
                    Some(crate::host_network::saved()?)
                } else {
                    None
                },
                general_open: mapping_open("oblivion-general")?,
                general_mounted: mode != MountMode::Closed,
                general_readonly: mode == MountMode::ReadOnly,
                session_open: mapping_open("oblivion-session")?,
                session_titles: session_titles(&mode)?,
                sessions: if mode == MountMode::ReadWrite {
                    sessions(".luks")?
                } else {
                    Vec::new()
                },
                incomplete_sessions: if mode == MountMode::ReadWrite {
                    sessions(".pending")?
                } else {
                    Vec::new()
                },
                available_bytes: if mode == MountMode::ReadWrite {
                    Some(available_bytes()?)
                } else {
                    None
                },
                session_bytes: config.session_mib * MIB,
                vm_state: if config.vm.is_some() {
                    Some(crate::vm::state()?)
                } else {
                    None
                },
                laboratory_emulation: cfg!(feature = "lab-emulation"),
                transfers_configured: config.import.is_some() || config.export.is_some(),
                gateway_network: config.gateway_network,
                recovery_required: recovery_required()?
                    || session_info()?.is_some_and(|(_, mode)| mode == "starting"),
                gateway_state: if config.gateway.is_some() {
                    Some(crate::gateway::state()?)
                } else {
                    None
                },
                gateway_vm_state: if config.gateway.is_some() {
                    Some(crate::vm::state_role(crate::vm::Role::Gateway)?)
                } else {
                    None
                },
                api_key_present: api_keys.as_ref().map(|keys| keys.selected.is_some()),
                api_keys,
                network_policy: {
                    let (saved, selected) = policy_profiles()?;
                    Some(network::Status::new(saved, selected))
                },
                egress: {
                    let (saved, selected) = transport_profiles()?;
                    Some(egress::Status {
                        saved: saved.metadata(),
                        selected: selected.as_ref().unwrap_or(&saved).metadata(),
                        temporary: selected.is_some(),
                    })
                },
            };
            println!(
                "{}",
                serde_json::to_string(&status).map_err(|_| Error("encode_failed"))?
            );
            Ok(())
        }
        _ => Err(Error("unknown_operation")),
    }
}

impl Config {
    fn change_network_policy(&self, command: network::Command) -> Result<()> {
        let mode = mount_mode()?;
        require(mode != MountMode::Closed, "general_not_open")?;
        require(credentials_editable()?, "session_must_be_closed")?;
        let (saved, selected) = policy_profiles()?;
        let mut policy = selected.or(saved).unwrap_or_default();
        let save = match command {
            network::Command::Saved {} => return clear_network_selection(),
            network::Command::Put { rule, save } => {
                require(
                    !save || mode == MountMode::ReadWrite,
                    "general_not_writable",
                )?;
                policy.put(rule).map_err(Error)?;
                save
            }
            network::Command::Remove { rule, save } => {
                require(
                    !save || mode == MountMode::ReadWrite,
                    "general_not_writable",
                )?;
                policy.remove(&rule).map_err(Error)?;
                save
            }
        };
        let path = Path::new(if save { PROFILE } else { RUN }).join(if save {
            "network-policy.json"
        } else {
            "network-policy-selection.json"
        });
        write_network_policy(&path, &policy, save)?;
        // Publish the complete saved policy before discarding a RAM selection.
        // A failed write must preserve both the previous file and selection.
        if save {
            clear_network_selection()?;
        }
        Ok(())
    }

    fn change_transport(&self, command: egress::Command) -> Result<()> {
        let mode = mount_mode()?;
        require(mode != MountMode::Closed, "general_not_open")?;
        let save = matches!(command, egress::Command::Save { .. });
        let temporary = matches!(command, egress::Command::Select { .. });
        require(
            !save || mode == MountMode::ReadWrite,
            "general_not_writable",
        )?;
        require(credentials_editable()?, "session_must_be_closed")?;
        let (saved, _) = transport_profiles()?;
        let profile = match command {
            egress::Command::Save { transport } | egress::Command::Select { transport } => {
                egress::Profile::new(transport).map_err(Error)?
            }
            egress::Command::Saved {} => saved,
        };
        require(
            self.gateway_network
                || matches!(profile.metadata(), oblivion_transport::Metadata::Tor {}),
            "external_proxy_requires_network",
        )?;
        // Close delegated connections before changing either stored or volatile
        // credentials. Any failed write leaves the gateway stopped.
        if self.gateway.is_some() {
            crate::gateway::stop()?;
        }
        if temporary {
            write_transport_profile(
                &Path::new(RUN).join("transport-selection.json"),
                &profile,
                false,
            )?;
        } else {
            clear_transport_selection()?;
            if save {
                write_transport_profile(
                    &Path::new(PROFILE).join("transport.json"),
                    &profile,
                    true,
                )?;
            }
        }
        Ok(())
    }

    fn change_keys(&self, command: keys::Command) -> Result<()> {
        let mode = mount_mode()?;
        require(mode != MountMode::Closed, "general_not_open")?;
        let mut keyring = read_keyring()?;
        let revoke = keyring.requires_revocation(&command, key_selection()?);
        let temporary = match &command {
            keys::Command::Temporary { .. } => true,
            keys::Command::Replace { id, .. }
            | keys::Command::Rename { id, .. }
            | keys::Command::Remove { id } => keyring.temporary.key(id).is_some(),
            _ => false,
        };
        require(
            mode == MountMode::ReadWrite
                || temporary
                || matches!(
                    command,
                    keys::Command::Select { .. } | keys::Command::Default { .. }
                ),
            "general_not_writable",
        )?;
        require(credentials_editable()?, "session_must_be_closed")?;
        if let keys::Command::Default { id } = &command {
            require(keyring.key(id).is_some(), "api_key_missing")?;
            if revoke && self.gateway.is_some() {
                crate::gateway::stop()?;
            }
            if mode == MountMode::ReadOnly || keyring.temporary.key(id).is_some() {
                return write_key_file("api-key-default", id.as_bytes());
            }
            keyring.saved.change(command).map_err(Error)?;
            save_api_keys(&keyring.saved)?;
            return clear_key_file("api-key-default");
        }
        let before = keyring.status(key_selection()?);
        let selecting = matches!(command, keys::Command::Select { .. });
        let selection = match command {
            keys::Command::Select { id } => {
                require(keyring.key(&id).is_some(), "api_key_missing")?;
                Some(id)
            }
            keys::Command::Temporary {
                provider,
                name,
                key,
            } => {
                keyring
                    .temporary
                    .change(keys::Command::Add {
                        provider,
                        name,
                        key,
                    })
                    .map_err(Error)?;
                let id = keyring
                    .temporary
                    .status(None)
                    .entries
                    .pop()
                    .ok_or(Error("api_key_missing"))?
                    .id;
                require(keyring.saved.key(&id).is_none(), "key_id_exists")?;
                Some(id)
            }
            command => {
                if temporary {
                    keyring.temporary.change(command).map_err(Error)?;
                } else {
                    keyring.saved.change(command).map_err(Error)?;
                }
                None
            }
        };
        // Retrying an opening with the same key must not restart Tor bootstrap.
        // Still record the explicit choice, independently of the saved default.
        if let Some(id) = selection.as_deref() {
            if before.selected.as_deref() == Some(id)
                && (self.gateway.is_none()
                    || (crate::gateway::state()? == "active"
                        && crate::vm::state_role(crate::vm::Role::Gateway)? == "active"))
            {
                return write_key_selection(Some(id));
            }
        }
        // No old credential remains delegated across a profile/selection change,
        // including a failed write. Restart requires the selected key to exist.
        if revoke && self.gateway.is_some() {
            crate::gateway::stop()?;
        }
        if temporary {
            write_key_file("api-keys.json", &keyring.temporary.encode().map_err(Error)?)?;
        } else if !selecting {
            save_api_keys(&keyring.saved)?;
        }
        if let Some(id) = selection {
            write_key_selection(Some(&id))?;
        } else if before.entries.is_empty() {
            clear_key_selection()?;
        } else if before
            .selected
            .as_ref()
            .is_some_and(|id| keyring.key(id).is_none())
        {
            write_key_selection(None)?;
        }
        Ok(())
    }

    fn start_gateway(&self, wait: bool) -> Result<()> {
        if self.gateway.is_some()
            && api_key_present()?
            && matches!(crate::gateway::state()?.as_str(), "inactive" | "failed")
        {
            crate::gateway::start(wait)?;
        }
        Ok(())
    }

    fn read(path: &Path) -> Result<Self> {
        let file = trusted_file(path)?;
        require(
            file.metadata()
                .map_err(|_| Error("config_unavailable"))?
                .len()
                <= 4096,
            "config_too_large",
        )?;
        let mut config: Self =
            serde_json::from_reader(file).map_err(|_| Error("invalid_config"))?;
        require(config.general_image.is_absolute(), "invalid_image_path")?;
        require(config.manager_uid > 0, "manager_must_not_be_root")?;
        require(
            config.general_mib >= 512 && config.general_mib <= 1024 * 1024,
            "invalid_general_size",
        )?;
        require(
            config.session_mib >= 128 && config.session_mib < config.general_mib,
            "invalid_session_size",
        )?;
        require(
            (65536..=1048576).contains(&config.pbkdf_memory_kib),
            "invalid_kdf_memory",
        )?;
        if config.usb_persistence {
            let usb = crate::usb::inspect(config.general_mib * MIB);
            // An unavailable medium must never fall back to a RAM archive.
            config.general_image = usb
                .source
                .clone()
                .unwrap_or_else(|| PathBuf::from("/run/oblivion/unprepared-usb"));
            config.usb = Some(usb);
        }
        Ok(config)
    }

    fn initialize(&self, secret: &[u8]) -> Result<()> {
        require(
            !mapping_open("oblivion-general")? && !mapping_open("oblivion-session")?,
            "volume_busy",
        )?;
        // Only a NEW regular file can be initialized. Physical devices and existing
        // files cannot be formatted through this interface, even with a bad password.
        require(
            !self
                .general_image
                .try_exists()
                .map_err(|_| Error("image_check_failed"))?,
            "general_already_exists",
        )?;
        let path = self.pending_general();
        create_image(&path, self.general_mib)?;
        self.format(&path, secret)?;
        crypt_open(&path, "oblivion-general", secret, false)?;
        let formatted = run(
            "/usr/sbin/mkfs.ext4",
            &[
                "-q",
                "-m",
                "0",
                "-E",
                "lazy_itable_init=0,lazy_journal_init=0",
                GENERAL,
            ],
            None,
        );
        let closed = crypt_close("oblivion-general");
        formatted?;
        closed?;
        publish(&path, &self.general_image)
    }

    fn pending_general(&self) -> PathBuf {
        let mut path = self.general_image.as_os_str().to_owned();
        path.push(".pending");
        PathBuf::from(path)
    }

    fn unlock(&self, secret: &[u8], readonly: bool) -> Result<()> {
        require(
            !mapping_open("oblivion-general")? && mount_mode()? == MountMode::Closed,
            "general_already_open",
        )?;
        if let Some(usb) = &self.usb {
            require(
                usb.status.present && usb.source.is_some(),
                "usb_general_unavailable",
            )?;
        } else {
            trusted_file(&self.general_image)?;
        }
        crypt_open(&self.general_image, "oblivion-general", secret, readonly)?;
        fs::create_dir_all(MOUNT).map_err(|_| Error("mount_directory_failed"))?;
        let result = run(
            "/usr/bin/mount",
            &[
                "-t",
                "ext4",
                "-o",
                if readonly {
                    "ro,noload,nodev,nosuid,noexec"
                } else {
                    "nodev,nosuid,noexec"
                },
                GENERAL,
                MOUNT,
            ],
            None,
        );
        if result.is_err() {
            crypt_close("oblivion-general")?;
            return result;
        }
        if readonly {
            return Ok(());
        }
        fs::set_permissions(MOUNT, fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("permissions_failed"))?;
        fs::create_dir_all(format!("{MOUNT}/sessions")).map_err(|_| Error("directory_failed"))?;
        fs::create_dir_all(format!("{MOUNT}/profile")).map_err(|_| Error("directory_failed"))?;
        Ok(())
    }

    fn create(&self, secret: &[u8]) -> Result<()> {
        require(
            mount_mode()? == MountMode::ReadWrite && mapping_open("oblivion-general")?,
            "general_not_writable",
        )?;
        require(!mapping_open("oblivion-session")?, "session_already_open")?;
        let id = random_id()?;
        let path = PathBuf::from(format!("{MOUNT}/sessions/{id}.pending"));
        create_image(&path, self.session_mib)?;
        self.format(&path, secret)?;
        crypt_open(&path, "oblivion-session", secret, false)?;
        let formatted = format_session();
        let closed = crypt_close("oblivion-session");
        formatted?;
        closed?;
        publish(&path, &PathBuf::from(format!("{MOUNT}/sessions/{id}.luks")))?;
        println!("{id}");
        Ok(())
    }

    fn prepare_backup(&self, id: &str, secret: &[u8]) -> Result<()> {
        require((1..=1024).contains(&secret.len()), "invalid_secret_length")?;
        closed_session_file(id)?;
        let vm = self.vm.as_ref().ok_or(Error("vm_not_configured"))?;
        vm.validate()?;
        let metadata = oblivion_host::backup::Metadata {
            format: "oblivion-session".into(),
            version: 1,
            original_id: id.into(),
            title: session_titles(&MountMode::ReadWrite)?.remove(id),
        };
        let result = (|| {
            self.open(id, secret)?;
            write_session_info(id, "starting")?;
            vm.start_documents()?;
            write_session_info(id, "documents")?;
            match session_export(oblivion_host::chat_export::Request::Checkpoint { metadata })? {
                oblivion_host::chat_export::Response::Metadata { .. } => Ok(()),
                oblivion_host::chat_export::Response::Rejected { error } => {
                    Err(Error(match error {
                        oblivion_host::backup::Rejection::UnsupportedVersion => {
                            "unsupported_backup_version"
                        }
                        oblivion_host::backup::Rejection::InvalidMetadata => {
                            "invalid_backup_metadata"
                        }
                        oblivion_host::backup::Rejection::InvalidDatabase => {
                            "invalid_backup_database"
                        }
                    }))
                }
                _ => Err(Error("invalid_backup_metadata")),
            }
        })();
        close_maintenance_session()?;
        result
    }

    fn finish_restore(&self, id: &str, secret: &[u8]) -> Result<()> {
        require((1..=1024).contains(&secret.len()), "invalid_secret_length")?;
        closed_archive()?;
        restore_receipt(id)?;
        let vm = self.vm.as_ref().ok_or(Error("vm_not_configured"))?;
        vm.validate()?;
        let path = Path::new(MOUNT).join(format!("sessions/{id}.pending"));
        let result = (|| {
            crypt_open(&path, "oblivion-session", secret, false)?;
            write_session_info(id, "starting")?;
            vm.start_documents()?;
            write_session_info(id, "documents")?;
            match session_export(oblivion_host::chat_export::Request::Inspect)? {
                oblivion_host::chat_export::Response::Metadata { metadata } => Ok(metadata),
                oblivion_host::chat_export::Response::Rejected { error } => {
                    Err(Error(match error {
                        oblivion_host::backup::Rejection::UnsupportedVersion => {
                            "unsupported_backup_version"
                        }
                        oblivion_host::backup::Rejection::InvalidMetadata => {
                            "invalid_backup_metadata"
                        }
                        oblivion_host::backup::Rejection::InvalidDatabase => {
                            "invalid_backup_database"
                        }
                    }))
                }
                _ => Err(Error("invalid_backup_metadata")),
            }
        })();
        close_maintenance_session()?;
        let metadata = result?;
        if let Some(title) = metadata.title {
            write_session_title(id, &title)?;
        }
        publish(&path, &Path::new(MOUNT).join(format!("sessions/{id}.luks")))?;
        discard_restore_record(id)
    }

    fn open_ephemeral(&self) -> Result<()> {
        require(
            mount_mode()? == MountMode::ReadOnly && mapping_open("oblivion-general")?,
            "ephemeral_boot_required",
        )?;
        require(!mapping_open("oblivion-session")?, "session_already_open")?;
        // runtime() checks tmpfs; secure_process() rejects swap. Reuse the same
        // block mapping/interlock, with a new random secret that is never saved.
        runtime()?;
        let mut secret = Zeroizing::new(vec![0; 64]);
        File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut secret))
            .map_err(|_| Error("random_failed"))?;
        create_image(Path::new(EPHEMERAL), self.session_mib)?;
        self.format(Path::new(EPHEMERAL), &secret)?;
        crypt_open(Path::new(EPHEMERAL), "oblivion-session", &secret, false)?;
        drop(secret);
        format_session()
    }

    fn open(&self, id: &str, secret: &[u8]) -> Result<()> {
        validate_id(id)?;
        require(
            mount_mode()? == MountMode::ReadWrite && mapping_open("oblivion-general")?,
            "general_not_writable",
        )?;
        // Kernel mapping is the interlock, not a JSON state file that can become stale.
        require(!mapping_open("oblivion-session")?, "session_already_open")?;
        let path = PathBuf::from(format!("{MOUNT}/sessions/{id}.luks"));
        trusted_file(&path)?;
        crypt_open(&path, "oblivion-session", secret, false)
    }

    fn format(&self, path: &Path, secret: &[u8]) -> Result<()> {
        run(
            "/usr/sbin/cryptsetup",
            &[
                "luksFormat",
                "--batch-mode",
                "--type",
                "luks2",
                "--cipher",
                "aes-xts-plain64",
                "--key-size",
                "512",
                "--pbkdf",
                "argon2id",
                "--pbkdf-memory",
                &self.pbkdf_memory_kib.to_string(),
                "--pbkdf-parallel",
                "1",
                "--iter-time",
                "1000",
                "--key-file",
                "-",
                path.to_str().ok_or(Error("invalid_path"))?,
            ],
            Some(secret),
        )
    }
}

fn profile_directory() -> Result<bool> {
    let directory = match fs::symlink_metadata(PROFILE) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(Error("profile_unavailable")),
        Ok(directory) => directory,
    };
    require(
        directory.is_dir() && directory.uid() == 0 && directory.mode() & 0o077 == 0,
        "unsafe_profile",
    )?;
    Ok(true)
}

fn read_api_keys() -> Result<keys::Archive> {
    if !profile_directory()? {
        return Ok(keys::Archive::empty());
    }
    for name in ["provider.keys.json", "abliteration.keys.json"] {
        if let Some(archive) = read_key_archive(&Path::new(PROFILE).join(name))? {
            return Ok(archive);
        }
    }
    let path = Path::new(PROFILE).join("abliteration.key");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(keys::Archive::empty());
        }
        Err(_) => return Err(Error("profile_unavailable")),
        Ok(_) => {}
    }
    let mut key = Zeroizing::new(String::new());
    trusted_file(&path)?
        .take(1025)
        .read_to_string(&mut key)
        .map_err(|_| Error("invalid_api_key"))?;
    keys::Archive::legacy(key).map_err(Error)
}

fn read_key_archive(path: &Path) -> Result<Option<keys::Archive>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error("profile_unavailable")),
        Ok(_) => {}
    }
    let mut bytes = Zeroizing::new(Vec::new());
    trusted_file(path)?
        .take(keys::LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("profile_unavailable"))?;
    keys::Archive::decode(&bytes).map(Some).map_err(Error)
}

fn read_keyring() -> Result<keys::Keyring> {
    let mut keyring = keys::Keyring::new(
        read_api_keys()?,
        read_key_archive(&Path::new(RUN).join("api-keys.json"))?
            .unwrap_or_else(keys::Archive::empty),
    )
    .map_err(Error)?;
    keyring.default = key_reference("api-key-default")?;
    Ok(keyring)
}

fn api_key_present() -> Result<bool> {
    Ok(read_keyring()?.status(key_selection()?).selected.is_some())
}

pub(crate) struct ApiKey {
    pub provider: Provider,
    pub secret: Zeroizing<Vec<u8>>,
}

fn read_api_key() -> Result<ApiKey> {
    let archive = read_keyring()?;
    let id = archive
        .status(key_selection()?)
        .selected
        .ok_or(Error("api_key_missing"))?;
    Ok(ApiKey {
        provider: archive.provider(&id).ok_or(Error("api_key_missing"))?,
        secret: Zeroizing::new(
            archive
                .key(&id)
                .ok_or(Error("api_key_missing"))?
                .as_bytes()
                .to_vec(),
        ),
    })
}

fn selected_provider() -> Result<Provider> {
    let keyring = read_keyring()?;
    let id = keyring
        .status(key_selection()?)
        .selected
        .ok_or(Error("api_key_missing"))?;
    keyring.provider(&id).ok_or(Error("api_key_missing"))
}

// Absence uses the saved default. An empty selection explicitly disables it;
// removing a selected key must never silently select another account.
fn key_selection() -> Result<Option<Option<String>>> {
    key_reference("api-key-selection")
}

fn key_reference(name: &str) -> Result<Option<Option<String>>> {
    let path = Path::new(RUN).join(name);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error("selection_unavailable")),
        Ok(_) => {}
    }
    let mut id = String::new();
    trusted_file(&path)?
        .take(33)
        .read_to_string(&mut id)
        .map_err(|_| Error("selection_unavailable"))?;
    require(
        id.is_empty() || keys::valid_id(&id),
        "invalid_key_selection",
    )?;
    Ok(Some(if id.is_empty() { None } else { Some(id) }))
}

fn clear_key_selection() -> Result<()> {
    clear_key_file("api-key-selection")
}

fn clear_key_file(name: &str) -> Result<()> {
    for name in [name.to_owned(), format!("{name}.pending")] {
        let path = Path::new(RUN).join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("selection_unavailable")),
            Ok(_) => {}
        }
        trusted_file(&path)?;
        fs::remove_file(path).map_err(|_| Error("selection_write_failed"))?;
    }
    Ok(())
}

fn write_key_selection(id: Option<&str>) -> Result<()> {
    write_key_file("api-key-selection", id.unwrap_or("").as_bytes())
}

fn write_key_file(name: &str, bytes: &[u8]) -> Result<()> {
    let path = Path::new(RUN).join(name);
    let pending = Path::new(RUN).join(format!("{name}.pending"));
    for existing in [&path, &pending] {
        match fs::symlink_metadata(existing) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("selection_unavailable")),
            Ok(_) => {
                trusted_file(existing)?;
            }
        }
    }
    if pending.exists() {
        fs::remove_file(&pending).map_err(|_| Error("selection_write_failed"))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|_| Error("selection_write_failed"))?;
    file.write_all(bytes)
        .map_err(|_| Error("selection_write_failed"))?;
    fs::rename(pending, path).map_err(|_| Error("selection_write_failed"))
}

fn transport_profiles() -> Result<(egress::Profile, Option<egress::Profile>)> {
    let saved = if profile_directory()? {
        read_transport_profile(&Path::new(PROFILE).join("transport.json"))?.unwrap_or_default()
    } else {
        egress::Profile::default()
    };
    // A corrupt saved profile is never hidden by a volatile override.
    Ok((
        saved,
        read_transport_profile(&Path::new(RUN).join("transport-selection.json"))?,
    ))
}

fn policy_profiles() -> Result<(Option<Policy>, Option<Policy>)> {
    let saved = if profile_directory()? {
        read_network_policy(&Path::new(PROFILE).join("network-policy.json"))?
    } else {
        None
    };
    Ok((
        saved,
        read_network_policy(&Path::new(RUN).join("network-policy-selection.json"))?,
    ))
}

fn read_network_policy(path: &Path) -> Result<Option<Policy>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error("network_policy_unavailable")),
        Ok(_) => {}
    }
    let mut bytes = Zeroizing::new(Vec::new());
    trusted_file(path)?
        .take(network::LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("network_policy_unavailable"))?;
    require(bytes.len() <= network::LIMIT, "invalid_network_policy")?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| Error("invalid_network_policy"))
}

fn clear_network_selection() -> Result<()> {
    for name in [
        "network-policy-selection.json",
        "network-policy-selection.json.pending",
    ] {
        let path = Path::new(RUN).join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("selection_unavailable")),
            Ok(_) => {}
        }
        trusted_file(&path)?;
        fs::remove_file(path).map_err(|_| Error("selection_write_failed"))?;
    }
    Ok(())
}

fn write_network_policy(path: &Path, policy: &Policy, durable: bool) -> Result<()> {
    let pending = path.with_extension("json.pending");
    for existing in [path, &pending] {
        match fs::symlink_metadata(existing) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("network_policy_unavailable")),
            Ok(_) => {
                trusted_file(existing)?;
            }
        }
    }
    let bytes = Zeroizing::new(
        serde_json::to_vec(policy).map_err(|_| Error("network_policy_encode_failed"))?,
    );
    require(bytes.len() <= network::LIMIT, "invalid_network_policy")?;
    if pending.exists() {
        fs::remove_file(&pending).map_err(|_| Error("network_policy_write_failed"))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|_| Error("network_policy_write_failed"))?;
    file.write_all(&bytes)
        .map_err(|_| Error("network_policy_write_failed"))?;
    if durable {
        file.sync_all()
            .map_err(|_| Error("network_policy_write_failed"))?;
    }
    fs::rename(pending, path).map_err(|_| Error("network_policy_write_failed"))?;
    if durable {
        sync_directory(path.parent().ok_or(Error("invalid_path"))?)?;
    }
    Ok(())
}

fn read_transport_profile(path: &Path) -> Result<Option<egress::Profile>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error("transport_profile_unavailable")),
        Ok(_) => {}
    }
    let mut bytes = Zeroizing::new(Vec::new());
    trusted_file(path)?
        .take(egress::LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("transport_profile_unavailable"))?;
    Ok(Some(egress::Profile::decode(&bytes).map_err(Error)?))
}

fn clear_transport_selection() -> Result<()> {
    for name in [
        "transport-selection.json",
        "transport-selection.json.pending",
    ] {
        let path = Path::new(RUN).join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("selection_unavailable")),
            Ok(_) => {}
        }
        trusted_file(&path)?;
        fs::remove_file(path).map_err(|_| Error("selection_write_failed"))?;
    }
    Ok(())
}

fn write_transport_profile(path: &Path, profile: &egress::Profile, durable: bool) -> Result<()> {
    let pending = path.with_extension("json.pending");
    for existing in [path, &pending] {
        match fs::symlink_metadata(existing) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error("transport_profile_unavailable")),
            Ok(_) => {
                trusted_file(existing)?;
            }
        }
    }
    if pending.exists() {
        fs::remove_file(&pending).map_err(|_| Error("transport_write_failed"))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|_| Error("transport_write_failed"))?;
    file.write_all(&profile.encode().map_err(Error)?)
        .map_err(|_| Error("transport_write_failed"))?;
    if durable {
        file.sync_all()
            .map_err(|_| Error("transport_write_failed"))?;
    }
    fs::rename(pending, path).map_err(|_| Error("transport_write_failed"))?;
    if durable {
        sync_directory(path.parent().ok_or(Error("invalid_path"))?)?;
    }
    Ok(())
}

pub(crate) fn tor_state(
    purpose: oblivion_host::tor_profile::Purpose,
) -> Result<Option<oblivion_tor_state::State>> {
    oblivion_host::tor_profile::load(Path::new(PROFILE), purpose).map_err(Error)
}

pub(crate) fn tor_state_writable() -> Result<bool> {
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::statvfs(c"/run/oblivion/general/profile".as_ptr(), &mut stat) } == 0,
        "profile_unavailable",
    )?;
    Ok(stat.f_flag & libc::ST_RDONLY == 0)
}

pub(crate) fn save_tor_state(
    purpose: oblivion_host::tor_profile::Purpose,
    state: &oblivion_tor_state::State,
) -> Result<()> {
    require(tor_state_writable()?, "general_not_writable")?;
    oblivion_host::tor_profile::save(Path::new(PROFILE), purpose, state).map_err(Error)
}

fn save_api_keys(archive: &keys::Archive) -> Result<()> {
    let directory = Path::new(PROFILE);
    let path = directory.join("provider.keys.json");
    let pending = directory.join("provider.keys.json.pending");
    let mut legacy = Vec::new();
    for name in [
        "abliteration.key",
        "abliteration.key.pending",
        "abliteration.keys.json",
        "abliteration.keys.json.pending",
    ] {
        let file = directory.join(name);
        match fs::symlink_metadata(&file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error("profile_unavailable")),
            Ok(_) => {
                trusted_file(&file)?;
                legacy.push(file);
            }
        }
    }
    match fs::symlink_metadata(&pending) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error("profile_unavailable")),
        Ok(_) => {
            trusted_file(&pending)?;
            fs::remove_file(&pending).map_err(|_| Error("profile_write_failed"))?;
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|_| Error("profile_write_failed"))?;
    file.write_all(&archive.encode().map_err(Error)?)
        .and_then(|()| file.sync_all())
        .map_err(|_| Error("profile_write_failed"))?;
    fs::rename(pending, path).map_err(|_| Error("profile_write_failed"))?;
    sync_directory(directory)?;
    // The versioned archive is authoritative even if cleanup is interrupted.
    // Publish and fsync it before removing any legacy credential.
    for file in legacy {
        fs::remove_file(file).map_err(|_| Error("profile_write_failed"))?;
    }
    sync_directory(directory)
}

fn close_session() -> Result<()> {
    clear_key_file("session-title")?;
    if mapping_open("oblivion-session")? {
        // No deferred removal: a live guest/block handle keeps the interlock.
        crypt_close("oblivion-session")?;
    }
    require(!mapping_open("oblivion-session")?, "session_still_open")?;
    if Path::new(EPHEMERAL)
        .try_exists()
        .map_err(|_| Error("ephemeral_check_failed"))?
    {
        trusted_file(Path::new(EPHEMERAL))?;
        fs::remove_file(EPHEMERAL).map_err(|_| Error("ephemeral_cleanup_failed"))?;
    }
    Ok(())
}

pub(crate) fn closed_session_file(id: &str) -> Result<File> {
    validate_id(id)?;
    closed_archive()?;
    trusted_file(&Path::new(MOUNT).join(format!("sessions/{id}.luks")))
}

fn closed_archive() -> Result<()> {
    require(!recovery_required()?, "recovery_required")?;
    require(
        mount_mode()? == MountMode::ReadWrite && mapping_open("oblivion-general")?,
        "general_not_writable",
    )?;
    require(
        !mapping_open("oblivion-session")? && crate::vm::stopped()?,
        "session_must_be_closed",
    )
}

pub(crate) fn restore_budget() -> Result<u64> {
    closed_archive()?;
    let bytes = available_bytes()?
        .saturating_sub(16 * MIB)
        .min(oblivion_transfer::MAX_ENCRYPTED_VOLUME_BYTES);
    require(bytes >= 32 * MIB, "insufficient_restore_space")?;
    Ok(bytes)
}

pub(crate) fn create_restore_copy(id: &str) -> Result<File> {
    validate_id(id)?;
    closed_archive()?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(MOUNT).join(format!("sessions/{id}.pending")))
        .map_err(|_| Error("restore_create_failed"))
}

pub(crate) fn complete_restore_copy(receipt: &oblivion_transfer::Receipt) -> Result<()> {
    let path = Path::new(MOUNT).join(format!("sessions/{}.restore-tmp", receipt.id));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| Error("restore_record_failed"))?;
    file.write_all(&serde_json::to_vec(receipt).map_err(|_| Error("encode_failed"))?)
        .and_then(|()| file.sync_all())
        .map_err(|_| Error("restore_record_failed"))?;
    publish(
        &path,
        &Path::new(MOUNT).join(format!("sessions/{}.restore", receipt.id)),
    )
}

fn restore_receipt(id: &str) -> Result<oblivion_transfer::Receipt> {
    validate_id(id)?;
    let receipt: oblivion_transfer::Receipt = serde_json::from_reader(
        trusted_file(&Path::new(MOUNT).join(format!("sessions/{id}.restore")))?.take(1025),
    )
    .map_err(|_| Error("invalid_restore_record"))?;
    require(
        receipt.id == id
            && receipt.entries == 1
            && (32 * MIB..=oblivion_transfer::MAX_ENCRYPTED_VOLUME_BYTES).contains(&receipt.bytes)
            && receipt.manifest_sha256.len() == 64
            && receipt
                .manifest_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid_restore_record",
    )?;
    require(
        trusted_file(&Path::new(MOUNT).join(format!("sessions/{id}.pending")))?
            .metadata()
            .map_err(|_| Error("metadata_failed"))?
            .len()
            == receipt.bytes,
        "restore_copy_changed",
    )?;
    Ok(receipt)
}

pub(crate) fn cleanup_restore(id: &str) -> Result<()> {
    validate_id(id)?;
    if Path::new(MOUNT)
        .join(format!("sessions/{id}.restore"))
        .try_exists()
        .map_err(|_| Error("restore_record_failed"))?
    {
        restore_receipt(id)?;
        return Ok(());
    }
    let path = Path::new(MOUNT).join(format!("sessions/{id}.pending"));
    if path
        .try_exists()
        .map_err(|_| Error("restore_record_failed"))?
    {
        discard_pending(&path)?;
    }
    discard_restore_record(id)
}

fn discard_restore_record(id: &str) -> Result<()> {
    validate_id(id)?;
    for extension in ["restore", "restore-tmp"] {
        let path = Path::new(MOUNT).join(format!("sessions/{id}.{extension}"));
        if path
            .try_exists()
            .map_err(|_| Error("restore_record_failed"))?
        {
            trusted_file(&path)?;
            fs::remove_file(path).map_err(|_| Error("restore_record_failed"))?;
        }
    }
    if !Path::new(MOUNT)
        .join(format!("sessions/{id}.luks"))
        .try_exists()
        .map_err(|_| Error("restore_record_failed"))?
    {
        for extension in ["title", "title-tmp"] {
            let path = Path::new(MOUNT).join(format!("sessions/{id}.{extension}"));
            if path
                .try_exists()
                .map_err(|_| Error("restore_record_failed"))?
            {
                trusted_file(&path)?;
                fs::remove_file(path).map_err(|_| Error("restore_record_failed"))?;
            }
        }
    }
    sync_directory(&Path::new(MOUNT).join("sessions"))
}

fn close_maintenance_session() -> Result<()> {
    let stopped = crate::vm::stop(false);
    let closed = if stopped.is_ok() {
        close_session()
    } else {
        Err(Error("vm_still_running"))
    };
    if stopped.is_err() || closed.is_err() {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(RECOVERY)
            .map_err(|_| Error("recovery_marker_failed"))?;
        return Err(Error("maintenance_cleanup_required"));
    }
    clear_key_file("session-info")
}

fn format_session() -> Result<()> {
    // The host formats the block device but never mounts a session filesystem.
    run(
        "/usr/sbin/mkfs.ext4",
        &[
            "-q",
            "-m",
            "0",
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0",
            SESSION,
        ],
        None,
    )
}

fn close_general() -> Result<()> {
    close_session()?;
    if mount_mode()? != MountMode::Closed {
        run("/usr/bin/umount", &[MOUNT], None)?;
    }
    if mapping_open("oblivion-general")? {
        crypt_close("oblivion-general")?;
    }
    require(
        mount_mode()? == MountMode::Closed && !mapping_open("oblivion-general")?,
        "general_still_open",
    )
}

fn crypt_open(path: &Path, name: &str, secret: &[u8], readonly: bool) -> Result<()> {
    let mut args = vec![
        "open",
        "--type",
        "luks2",
        "--disable-external-tokens",
        "--key-file",
        "-",
        path.to_str().ok_or(Error("invalid_path"))?,
        name,
    ];
    if readonly {
        args.push("--readonly");
    }
    run("/usr/sbin/cryptsetup", &args, Some(secret)).map_err(|_| Error("volume_unlock_failed"))
}

fn crypt_close(name: &str) -> Result<()> {
    run("/usr/sbin/cryptsetup", &["close", name], None)
}

fn run(program: &str, args: &[&str], secret: Option<&[u8]>) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(if secret.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error("command_start_failed"))?;
    let input = match secret {
        Some(bytes) => child
            .stdin
            .take()
            .ok_or(Error("secret_pipe_failed"))?
            .write_all(bytes),
        None => Ok(()),
    };
    let status = child.wait().map_err(|_| Error("command_wait_failed"))?;
    input.map_err(|_| Error("secret_pipe_failed"))?;
    require(status.success(), "operation_failed")
}

fn secure_process() -> Result<()> {
    // These settings apply only to this process and its children, never the host OS.
    unsafe {
        require(libc::geteuid() == 0, "root_required")?;
        libc::umask(0o077);
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        require(
            libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0,
            "core_limit_failed",
        )?;
        require(
            libc::prctl(libc::PR_SET_DUMPABLE, 0) == 0,
            "dump_protection_failed",
        )?;
    }
    let swaps = fs::read_to_string("/proc/swaps").map_err(|_| Error("swap_check_failed"))?;
    require(swaps.lines().count() == 1, "swap_must_be_disabled")
}

fn lock() -> Result<File> {
    lock_named("storage.lock")
}

pub(crate) fn lock_named(name: &str) -> Result<File> {
    runtime()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(format!("{RUN}/{name}"))
        .map_err(|_| Error("lock_failed"))?;
    unsafe {
        require(
            libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0,
            "controller_busy",
        )?;
        // Trusted workers inherit the lock so a killed parent cannot release it
        // while cryptsetup or mkfs is still modifying a volume.
        require(
            libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) == 0,
            "lock_inheritance_failed",
        )?;
    }
    Ok(file)
}

pub(crate) fn recovery_required() -> Result<bool> {
    Path::new(RECOVERY)
        .try_exists()
        .map_err(|_| Error("recovery_check_failed"))
}

fn runtime() -> Result<()> {
    fs::create_dir_all(RUN).map_err(|_| Error("runtime_directory_failed"))?;
    let meta = fs::symlink_metadata(RUN).map_err(|_| Error("runtime_directory_failed"))?;
    require(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
        "unsafe_runtime_directory",
    )?;
    let runtime = File::open(RUN).map_err(|_| Error("runtime_directory_failed"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    unsafe {
        require(
            libc::fstatfs(runtime.as_raw_fd(), stats.as_mut_ptr()) == 0,
            "runtime_check_failed",
        )?;
        require(
            stats.assume_init().f_type == libc::TMPFS_MAGIC,
            "runtime_must_be_tmpfs",
        )?;
    }
    Ok(())
}

pub(crate) fn trusted_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error("file_unavailable"))?;
    let meta = file.metadata().map_err(|_| Error("metadata_failed"))?;
    require(
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o077 == 0 && meta.nlink() == 1,
        "unsafe_file",
    )?;
    Ok(file)
}

fn create_image(path: &Path, mib: u64) -> Result<()> {
    let parent = path.parent().ok_or(Error("invalid_image_path"))?;
    let meta = fs::symlink_metadata(parent).map_err(|_| Error("image_parent_unavailable"))?;
    require(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "unsafe_image_parent",
    )?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error("image_exists_or_unavailable"))?;
    file.set_len(mib * MIB)
        .map_err(|_| Error("image_size_failed"))?;
    // Reserve space up front: a sparse inner vault must not exhaust the general
    // filesystem while the guest believes it still has free disk blocks.
    // posix_fallocate returns an error number directly; it does not set errno.
    match unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, (mib * MIB) as libc::off_t) } {
        0 => {}
        libc::ENOSPC | libc::EDQUOT => return Err(Error("insufficient_space")),
        _ => return Err(Error("image_allocation_failed")),
    }
    file.sync_all().map_err(|_| Error("sync_failed"))?;
    sync_directory(parent)
}

fn publish(pending: &Path, destination: &Path) -> Result<()> {
    trusted_file(pending)?
        .sync_all()
        .map_err(|_| Error("sync_failed"))?;
    let source =
        CString::new(pending.as_os_str().as_encoded_bytes()).map_err(|_| Error("invalid_path"))?;
    let target = CString::new(destination.as_os_str().as_encoded_bytes())
        .map_err(|_| Error("invalid_path"))?;
    // Publication is atomic and must never replace an existing archive.
    require(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "publish_failed",
    )?;
    sync_directory(destination.parent().ok_or(Error("invalid_path"))?)
}

fn discard_pending(path: &Path) -> Result<()> {
    require(!mapping_open("oblivion-session")?, "volume_busy")?;
    trusted_file(path)?;
    fs::remove_file(path).map_err(|_| Error("discard_failed"))?;
    sync_directory(path.parent().ok_or(Error("invalid_path"))?)
}

fn available_bytes() -> Result<u64> {
    let file = File::open(MOUNT).map_err(|_| Error("space_check_failed"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    require(
        unsafe { libc::fstatvfs(file.as_raw_fd(), stats.as_mut_ptr()) } == 0,
        "space_check_failed",
    )?;
    let stats = unsafe { stats.assume_init() };
    Ok(stats.f_bavail.saturating_mul(stats.f_frsize))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| Error("sync_failed"))
}

fn mapping_open(name: &str) -> Result<bool> {
    // Device symlinks are managed asynchronously by userspace. Only the kernel's
    // device-mapper table can tell us that the mapping is really gone.
    for entry in fs::read_dir("/sys/block").map_err(|_| Error("mapping_check_failed"))? {
        let entry = entry.map_err(|_| Error("mapping_check_failed"))?;
        if !entry.file_name().to_string_lossy().starts_with("dm-") {
            continue;
        }
        let active = fs::read_to_string(entry.path().join("dm/name"))
            .map_err(|_| Error("mapping_check_failed"))?;
        if active.trim() == name {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(PartialEq)]
enum MountMode {
    Closed,
    ReadOnly,
    ReadWrite,
}

fn mount_mode() -> Result<MountMode> {
    let mounts =
        fs::read_to_string("/proc/self/mountinfo").map_err(|_| Error("mount_check_failed"))?;
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.get(4) == Some(&MOUNT) {
            let separator = fields
                .iter()
                .position(|field| *field == "-")
                .ok_or(Error("mount_check_failed"))?;
            require(
                fields.get(separator + 2) == Some(&GENERAL),
                "unexpected_general_mount",
            )?;
            let readonly = fields
                .get(5)
                .ok_or(Error("mount_check_failed"))?
                .split(',')
                .any(|option| option == "ro");
            return Ok(if readonly {
                MountMode::ReadOnly
            } else {
                MountMode::ReadWrite
            });
        }
    }
    Ok(MountMode::Closed)
}

fn write_session_title(id: &str, title: &str) -> Result<()> {
    let directory = Path::new(MOUNT).join("sessions");
    let path = directory.join(format!("{id}.title"));
    let pending = directory.join(format!("{id}.title-tmp"));
    for existing in [&path, &pending] {
        if fs::symlink_metadata(existing).is_ok() {
            trusted_file(existing)?;
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|_| Error("session_title_write_failed"))?;
    file.write_all(title.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| Error("session_title_write_failed"))?;
    fs::rename(pending, path).map_err(|_| Error("session_title_write_failed"))?;
    sync_directory(&directory)
}

fn session_titles(mode: &MountMode) -> Result<std::collections::BTreeMap<String, String>> {
    let mut titles = std::collections::BTreeMap::new();
    let paths: Vec<_> = match mode {
        MountMode::Closed => Vec::new(),
        MountMode::ReadWrite => sessions(".luks")?
            .into_iter()
            .map(|id| {
                (
                    id.clone(),
                    Path::new(MOUNT).join(format!("sessions/{id}.title")),
                )
            })
            .collect(),
        MountMode::ReadOnly => session_info()?
            .into_iter()
            .map(|(id, _)| (id, Path::new(RUN).join("session-title")))
            .collect(),
    };
    for (id, path) in paths {
        if !path
            .try_exists()
            .map_err(|_| Error("session_title_read_failed"))?
        {
            continue;
        }
        let mut title = String::new();
        trusted_file(&path)?
            .take(257)
            .read_to_string(&mut title)
            .map_err(|_| Error("session_title_read_failed"))?;
        oblivion_host::session_title::validate(&title).map_err(Error)?;
        titles.insert(id, title);
    }
    Ok(titles)
}

fn sessions(extension: &str) -> Result<Vec<String>> {
    let mut ids = Vec::new();
    for entry in
        fs::read_dir(format!("{MOUNT}/sessions")).map_err(|_| Error("session_list_failed"))?
    {
        let entry = entry.map_err(|_| Error("session_list_failed"))?;
        let name = entry.file_name();
        if let Some(id) = name.to_str().and_then(|name| name.strip_suffix(extension)) {
            validate_id(id)?;
            trusted_file(&entry.path())?;
            ids.push(id.to_owned());
        }
    }
    ids.sort();
    Ok(ids)
}

pub(crate) fn validate_id(id: &str) -> Result<()> {
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid_session_id",
    )
}

pub(crate) fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| Error("random_failed"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn password(creating: bool) -> Result<Zeroizing<Vec<u8>>> {
    // Binary stdin is a private pipe from the trusted UI, never argv, environment,
    // shell history or a temporary key file. Newline is part of the password.
    let mut bytes = Zeroizing::new(Vec::with_capacity(1025));
    std::io::stdin()
        .take(1025)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("secret_read_failed"))?;
    require(
        bytes.len() <= 1024 && bytes.len() >= if creating { 16 } else { 1 },
        "invalid_password_length",
    )?;
    Ok(bytes)
}

pub(crate) fn require(condition: bool, code: &'static str) -> Result<()> {
    if condition {
        return Ok(());
    }
    Err(Error(code))
}

// Display metadata is RAM-only. The kernel mapping remains the ownership interlock.
// Keep the already-unlocked volume, but revoke the failed chat before returning
// it to an offline guest. Any incomplete cleanup leaves recovery latched.
fn recover_chat(config: &Config) -> Result<()> {
    let (id, mode) = session_info()?.ok_or(Error("session_not_open"))?;
    require(mode == "starting", "chat_not_starting")?;
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(RECOVERY)
        .map_err(|_| Error("recovery_marker_failed"))?;
    if crate::gateway::revoke().is_err() {
        crate::gateway::shutdown()?;
    }
    crate::vm::stop(false)?;
    config
        .vm
        .as_ref()
        .ok_or(Error("vm_not_configured"))?
        .start_documents()?;
    write_session_info(&id, "documents")?;
    fs::remove_file(RECOVERY).map_err(|_| Error("recovery_clear_failed"))
}

pub(crate) fn session_info() -> Result<Option<(String, String)>> {
    if !mapping_open("oblivion-session")? {
        return Ok(None);
    }
    let path = Path::new(RUN).join("session-info");
    if !path.exists() {
        return Ok(None);
    }
    let value: (String, String) = serde_json::from_reader(trusted_file(&path)?.take(256))
        .map_err(|_| Error("invalid_session_state"))?;
    validate_id(&value.0)?;
    require(
        matches!(value.1.as_str(), "documents" | "chat" | "starting"),
        "invalid_session_state",
    )?;
    Ok(Some(value))
}
fn write_session_info(id: &str, mode: &str) -> Result<()> {
    write_key_file(
        "session-info",
        &serde_json::to_vec(&(id, mode)).map_err(|_| Error("encode_failed"))?,
    )
}
fn credentials_editable() -> Result<bool> {
    Ok(
        (!mapping_open("oblivion-session")? && crate::vm::stopped()?)
            || session_info()?.is_some_and(|(_, mode)| mode == "documents"),
    )
}

fn session_export(
    request: oblivion_host::chat_export::Request,
) -> Result<oblivion_host::chat_export::Response> {
    require(
        !recovery_required()? && mapping_open("oblivion-session")? && !crate::vm::stopped()?,
        "session_not_open",
    )?;
    require(request.valid(), "invalid_chat_export_request")?;
    let id = random_id()?;
    let result = (|| {
        use oblivion_transfer::endpoint::{read_message, write_message};
        let stream = crate::vm::chat_export_port(&id)?;
        let mut channel =
            oblivion_host::channel::Channel::new(&stream, std::time::Duration::from_secs(95));
        let mut ready = [0; 6];
        channel
            .read_exact(&mut ready)
            .map_err(|_| Error("chat_export_not_ready"))?;
        require(&ready == b"ready\n", "invalid_transfer_guest")?;
        channel
            .write_all(b"G")
            .map_err(|_| Error("chat_export_not_ready"))?;
        write_message(&mut channel, &request).map_err(|_| Error("chat_export_failed"))?;
        let response: oblivion_host::chat_export::Response =
            read_message(&mut channel, 64 * 1024).map_err(|_| Error("chat_export_failed"))?;
        require(response.valid(&request), "invalid_chat_export_response")?;
        require(
            !matches!(response, oblivion_host::chat_export::Response::Unavailable),
            "chat_export_unavailable",
        )?;
        Ok(response)
    })();
    let cleanup = crate::vm::remove_copy_port(&id);
    let response = result?;
    cleanup?;
    Ok(response)
}

fn diagnostic_report() -> Result<oblivion_host::diagnostics::Report> {
    use oblivion_host::diagnostics::{Architecture, Report, Session, Transport};
    let session = session_info()?;
    let observation = network_observation(session.as_ref().map(|(_, mode)| mode.as_str()));
    let system = crate::system_info::status();
    Ok(Report {
        version: 1,
        controller_version: env!("CARGO_PKG_VERSION").into(),
        architecture: match std::env::consts::ARCH {
            "aarch64" => Architecture::Aarch64,
            "x86_64" => Architecture::X86_64,
            _ => Architecture::Unknown,
        },
        cpu_cores: system.cores,
        memory_mib: system.memory_total / MIB,
        ephemeral: mount_mode()? == MountMode::ReadOnly,
        general_open: mapping_open("oblivion-general")?,
        session: if recovery_required()? {
            Session::Recovery
        } else {
            match session.as_ref().map(|(_, mode)| mode.as_str()) {
                Some("documents") => Session::Documents,
                Some("chat") => Session::Chat,
                Some("starting") => Session::Starting,
                _ => Session::Locked,
            }
        },
        transport: match observation.label.as_str() {
            "NOT STARTED" => Transport::NotStarted,
            "CONNECTING" => Transport::Connecting,
            "TOR READY" => Transport::Tor,
            "SOCKS5 READY" => Transport::Socks5,
            "OFFLINE" | "OFFLINE · NO NETWORK DEVICE" => Transport::Offline,
            _ => Transport::Unknown,
        },
        direct_access_blocked: observation.direct_blocked,
        observation_age_ms: observation.age_ms,
        tor_bootstrap: observation.tor_progress,
        laboratory: cfg!(feature = "lab-emulation"),
    })
}

fn network_observation(mode: Option<&str>) -> network::Observation {
    let host_link = fs::read_dir("/sys/class/net").ok().map(|entries| {
        entries.flatten().any(|entry| {
            entry.file_name() != "lo"
                && fs::read_to_string(entry.path().join("operstate"))
                    .is_ok_and(|state| state.trim() == "up")
        })
    });
    let mut result = network::Observation {
        label: "STATUS UNKNOWN".into(),
        host_link: match host_link {
            Some(true) => "CONNECTED",
            Some(false) => "OFFLINE",
            None => "STATUS UNKNOWN",
        }
        .into(),
        direct_blocked: false,
        age_ms: 0,
        tor_progress: None,
    };
    if mode == Some("documents") {
        if crate::vm::network_devices().is_ok_and(|count| count == 0) {
            result.label = "OFFLINE · NO NETWORK DEVICE".into();
            result.direct_blocked = true;
        }
        if let Ok(observed) = crate::gateway::observation() {
            if observed.age_ms <= 10000 {
                result.tor_progress = observed.tor_progress;
            }
        }
        return result;
    }
    let Ok(state) = crate::gateway::state() else {
        return result;
    };
    if matches!(state.as_str(), "inactive" | "failed") {
        result.label = if mode.is_some() {
            "OFFLINE"
        } else {
            "NOT STARTED"
        }
        .into();
        return result;
    }
    let Ok(observed) = crate::gateway::observation() else {
        return result;
    };
    result.age_ms = observed.age_ms;
    if observed.age_ms > 10000 {
        return result;
    }
    result.tor_progress = observed.tor_progress;
    result.direct_blocked = observed.isolated
        && (mode.is_none() || crate::vm::network_devices().is_ok_and(|count| count == 1));
    result.label = if !result.direct_blocked {
        "STATUS UNKNOWN"
    } else if !observed.ready {
        "CONNECTING"
    } else if observed.tor {
        "TOR READY"
    } else {
        "SOCKS5 READY"
    }
    .into();
    result
}
