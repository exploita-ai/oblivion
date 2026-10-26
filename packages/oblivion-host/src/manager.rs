use oblivion_host::control::{self, Result};
use oblivion_host::terminal::{self, ACTION, BRAND, CLEAR, FEEDBACK, LOGO, RESET, Terminal};
use oblivion_host::{egress, keys, network, persistence};
mod transfer_menu;
use oblivion_transport::policy::{Action, Rule};
use oblivion_transport::{Authentication, Metadata, Transport};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    general_present: bool,
    general_incomplete: bool,
    general_open: bool,
    general_mounted: bool,
    general_readonly: bool,
    session_open: bool,
    sessions: Vec<String>,
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
    #[serde(default, rename = "settings")]
    _settings: Option<oblivion_host::settings::Status>,
}

fn main() {
    let preview = std::env::args().nth(1).as_deref() == Some("--preview");
    if run(preview).is_err() {
        // A failed lock is not reported as success; a restarted manager queries
        // kernel-derived status again before enabling any new session operation.
        if !preview && cfg!(target_os = "linux") && unsafe { libc::geteuid() } != 0 {
            let _ = control::request("lock", None, &[]);
        }
        eprintln!("manager_stopped_check_controller_state");
        std::process::exit(1);
    }
}

fn run(preview: bool) -> Result<()> {
    control::protect()?;
    if !preview && (!cfg!(target_os = "linux") || unsafe { libc::geteuid() } == 0) {
        return Err("linux_nonroot_manager_required".into());
    }
    let mut terminal = Terminal::open()?;
    let storage_unavailable = std::env::var_os("OBLIVION_STORAGE_UNAVAILABLE").is_some();
    if preview {
        terminal.write(&format!("{CLEAR}{BRAND}{LOGO}{RESET}\r\n\r\n OBLIVION - ANTEPRIMA, nessun archivio collegato\r\n\r\n > Sessione 7c2a  Bloccata\r\n   Sessione 91f4  Bloccata\r\n\r\n {ACTION}Premi un tasto per uscire. Nessuna password richiesta.{RESET}"))?;
        terminal.input(-1)?;
        return Ok(());
    }
    let mut selected = 0usize;
    let mut notice = String::new();
    let mut requested_new = false;
    let mut incomplete = false;
    loop {
        let status: Status = serde_json::from_str(&control::request("status", None, &[])?)?;
        if status
            .sessions
            .iter()
            .chain(&status.incomplete_sessions)
            .any(|s| {
                s.len() != 32
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err("invalid_session_list".into());
        }
        let sessions = if incomplete {
            &status.incomplete_sessions
        } else {
            &status.sessions
        };
        selected = selected.min(sessions.len().saturating_sub(1));
        let (rows, cols) = terminal.size();
        let mut view = format!(
            "{CLEAR}{BRAND}{} OBLIVION - controllo fidato{RESET}\r\n\r\n",
            if cols >= 64 && rows >= 20 {
                format!("{LOGO}\r\n\r\n")
            } else {
                String::new()
            }
        );
        if status.laboratory_emulation {
            view.push_str(" LABORATORIO TCG - solo dati sintetici\r\n\r\n");
        }
        if status.persistence.is_some() {
            view.push_str(" Alt+F2: Wi-Fi / Ethernet   Alt+F1: torna qui\r\n");
        }
        if status.recovery_required {
            view.push_str(" RECUPERO NECESSARIO - nuove aperture bloccate\r\n\r\n [B] Riprova chiusura e blocco\r\n [F] Arresto forzato e blocco\r\n");
        } else if !status.general_mounted {
            view.push_str(if status.general_open {
                " Archivio generale da richiudere.\r\n\r\n [B] Blocca\r\n"
            } else if !status.general_present && status.general_incomplete {
                " Preparazione generale interrotta.\r\n Nessun archivio pronto; il tentativo incompleto e' conservato.\r\n\r\n [D] Elimina il tentativo incompleto\r\n"
            } else if !status.general_present {
                if let Some(reason) = status.persistence.as_ref().and_then(|usb| usb.unavailable.as_deref()) {
                    match reason {
                        "usb_no_free_space" => " Spazio USB insufficiente.\r\n Serve almeno lo spazio minimo previsto dopo l'immagine live.\r\n Usa una chiavetta di maggiore capacità.\r\n",
                        "usb_loop_boot_required" => " Questa immagine non supporta la preparazione USB.\r\n Avvia una versione Oblivion aggiornata.\r\n Nessuna partizione è stata modificata.\r\n",
                        "usb_foreign_partitions" => " La USB contiene partizioni non gestite da Oblivion.\r\n Preparazione bloccata per preservarle.\r\n",
                        _ => " Persistenza USB non disponibile.\r\n Avvia da una USB Oblivion scrivibile con spazio libero.\r\n Le partizioni estranee non vengono modificate.\r\n",
                    }
                } else if status.persistence.is_some() {
                    " Prima preparazione della USB Oblivion\r\n\r\n [Invio] Prepara lo spazio cifrato sulla USB di avvio\r\n"
                } else if storage_unavailable {
                    " ISO DI SVILUPPO - avvio del manager\r\n\r\n Supporto dati USB non ancora predisposto.\r\n Creazione degli archivi disabilitata.\r\n Nessun dato viene salvato in questa prova.\r\n"
                } else {
                    " Prima preparazione di Oblivion\r\n\r\n [Invio] Crea il volume generale cifrato\r\n"
                }
            } else {
                " Archivio generale bloccato\r\n\r\n [Invio] Sblocca  [E] Avvio effimero\r\n"
            });
        } else if status.session_open
            || !matches!(
                status.vm_state.as_deref(),
                None | Some("inactive" | "failed")
            )
        {
            view.push_str(if status.general_readonly {
                " SESSIONE EFFIMERA APERTA - dati solo in RAM\r\n Chiudere distrugge la conversazione.\r\n\r\n [Invio] Console   [C] Chiudi e distruggi\r\n [F] Chiusura forzata\r\n"
            } else {
                " SESSIONE ANCORA APERTA\r\n\r\n [Invio] Console   [C] Chiudi e blocca\r\n [F] Chiusura forzata\r\n"
            });
            if status.transfers_configured {
                view.push_str(" [D] Documenti: importa da USB\r\n");
            }
        } else if status.general_readonly {
            view.push_str(&format!(" Avvio effimero - profilo in sola lettura\r\n Sessioni solo in RAM: {} MiB ciascuna.\r\n La chiusura distrugge conversazione e documenti.\r\n\r\n [N/Invio] Nuova sessione effimera\r\n [G] Scegli chiave API  [R] Rete  [W] Regole web  [B] Blocca\r\n", status.session_bytes / 1048576));
        } else {
            view.push_str(if incomplete {
                " Creazioni interrotte - mai aperte come chat\r\n\r\n"
            } else {
                " Sessioni protette\r\n\r\n"
            });
            let limit = rows
                .saturating_sub(if rows >= 20 && cols >= 64 { 21 } else { 16 })
                .saturating_sub(u16::from(status.persistence.is_some()))
                .saturating_sub(u16::from(status.network_profiles_saved.is_some()))
                .max(1) as usize;
            let start = selected.saturating_sub(limit - 1);
            for (index, session) in sessions.iter().enumerate().skip(start).take(limit) {
                view.push_str(&format!(
                    " {} Sessione {}  {}\r\n",
                    if index == selected { ">" } else { " " },
                    &session[..8],
                    if incomplete { "Incompleta" } else { "Bloccata" }
                ));
            }
            if sessions.is_empty() {
                view.push_str(if incomplete {
                    " Nessuna creazione interrotta.\r\n"
                } else {
                    " Nessuna sessione.\r\n"
                });
            }
            view.push_str(&format!(
                "\r\n Spazio disponibile: {} MiB; nuova sessione: {} MiB\r\n",
                status.available_bytes.unwrap_or(0) / 1048576,
                status.session_bytes / 1048576
            ));
            view.push_str(&format!(
                " API Abliteration: {}  [A] Imposta  [X] Rimuovi  [G] Chiavi\r\n",
                if status.api_key_present == Some(true) {
                    "configurata"
                } else {
                    "non configurata"
                }
            ));
            if let Some(saved) = status.network_profiles_saved {
                view.push_str(&format!(
                    " Wi-Fi/Ethernet: {}  [P] Salva rete nel generale\r\n",
                    if saved {
                        "profilo salvato"
                    } else {
                        "solo in RAM"
                    }
                ));
            }
            if let Some(keys) = &status.api_keys {
                let name = keys
                    .entries
                    .iter()
                    .find(|entry| Some(&entry.id) == keys.selected.as_ref())
                    .map(|entry| entry.name.as_str())
                    .unwrap_or("nessuna");
                view.push_str(&format!(" Chiave selezionata: {name}\r\n"));
            }
            if let Some(egress) = &status.egress {
                view.push_str(&format!(
                    " Rete: {}{}  [R] Trasporto  [W] Regole web\r\n",
                    transport_label(&egress.selected),
                    if egress.temporary {
                        " (temporanea)"
                    } else {
                        ""
                    }
                ));
            }
            if let Some(gateway) = &status.gateway_state {
                view.push_str(
                    if gateway == "active" && status.gateway_vm_state.as_deref() == Some("active") {
                        if status.gateway_network {
                            if status.egress.as_ref().is_some_and(|egress| {
                                matches!(egress.selected, Metadata::Socks5 { .. })
                            }) {
                                " Gateway avviato con SOCKS5.\r\n"
                            } else {
                                " Gateway avviato. Tor può richiedere alcuni istanti.\r\n"
                            }
                        } else {
                            " Gateway pronto; rete non abilitata.\r\n"
                        }
                    } else {
                        " Gateway non attivo.\r\n"
                    },
                );
            }
            view.push_str(&format!(
                " {ACTION}{}\r\n [I] Creazioni interrotte ({}) / sessioni  [B] Blocca{RESET}\r\n",
                if incomplete {
                    "[D] Elimina selezionata  [J/K] Seleziona"
                } else {
                    "[N] Nuova  [Invio] Apri  [J/K] Seleziona"
                },
                status.incomplete_sessions.len()
            ));
        }
        view.push_str(&format!(
            "\r\n {FEEDBACK}{notice}{RESET}\r\n [Q] Blocca tutto ed esci"
        ));
        terminal.write(&view)?;
        let input = if std::mem::take(&mut requested_new) {
            zeroize::Zeroizing::new(vec![b'n'])
        } else {
            terminal.input(-1)?
        };
        let key = if input.as_slice() == b"\x1b[A" {
            b'k'
        } else if input.as_slice() == b"\x1b[B" {
            b'j'
        } else if input.len() == 1 {
            input[0].to_ascii_lowercase()
        } else {
            continue;
        };
        notice.clear();
        if key == b'j' {
            selected = (selected + 1).min(sessions.len().saturating_sub(1));
            continue;
        }
        if key == b'k' {
            selected = selected.saturating_sub(1);
            continue;
        }
        let result: Result<()> = (|| {
            if matches!(key, b'b' | b'q') {
                busy(&mut terminal, "Blocco di Oblivion in corso")?;
                control::request("lock", None, &[])?;
                return Ok(());
            }
            if key == b'p'
                && status.network_profiles_saved.is_some()
                && !status.general_readonly
                && !status.session_open
            {
                busy(
                    &mut terminal,
                    "Salvataggio della configurazione di rete cifrata",
                )?;
                control::request("save-network", None, &[])?;
                return Ok(());
            }
            if !status.recovery_required
                && !status.general_open
                && matches!(key, b'\r' | b'\n' | b'e')
            {
                if !status.general_present {
                    if key == b'e' || (storage_unavailable && status.persistence.is_none()) {
                        return Ok(());
                    }
                    if let Some(usb) = &status.persistence {
                        if usb.unavailable.is_some() {
                            return Ok(());
                        }
                        if !usb.incomplete {
                            let plan = usb.plan.as_ref().ok_or("usb_plan_missing")?;
                            terminal.flush_input();
                            terminal.write(&format!("{CLEAR}{BRAND} PREPARA USB OBLIVION{RESET}\r\n\r\n USB di avvio: /dev/{} ({} MiB)\r\n Nuovo spazio cifrato: {} MiB\r\n\r\n Usa lo spazio non partizionato dopo il sistema live.\r\n Eventuali vecchi dati in quello spazio saranno sovrascritti.\r\n\r\n [S] Conferma questa USB  [Esc] Annulla", plan.device, plan.disk_bytes / 1048576, plan.sectors / 2048))?;
                            if !matches!(terminal.input(-1)?.as_slice(), b"s" | b"S") {
                                return Ok(());
                            }
                            if let Some(secret) = new_password(
                                &mut terminal,
                                "Nuovo volume generale - password di almeno 16 byte",
                                "Ripeti la password del volume generale",
                            )? {
                                let request = persistence::Prepare {
                                    plan: plan.clone(),
                                    password: zeroize::Zeroizing::new(
                                        std::str::from_utf8(&secret)?.to_owned(),
                                    ),
                                };
                                let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&request)?);
                                busy(&mut terminal, "Preparazione dello spazio cifrato sulla USB")?;
                                control::request("prepare-usb", None, &bytes)?;
                            }
                        }
                        return Ok(());
                    }
                    if !status.general_incomplete {
                        if let Some(secret) = new_password(
                            &mut terminal,
                            "Nuovo volume generale - password di almeno 16 byte",
                            "Ripeti la password del volume generale",
                        )? {
                            busy(&mut terminal, "Preparazione del volume generale cifrato")?;
                            control::request("init-general", None, &secret)?;
                        }
                    }
                    return Ok(());
                }
                if let Some(secret) = terminal.password(if key == b'e' {
                    "Password del volume generale - avvio effimero, sola lettura"
                } else {
                    "Password del volume generale"
                })? {
                    busy(&mut terminal, "Sblocco del volume generale")?;
                    control::request(
                        if key == b'e' {
                            "unlock-ephemeral"
                        } else {
                            "unlock"
                        },
                        None,
                        &secret,
                    )?;
                }
                return Ok(());
            }
            if status.recovery_required || status.session_open {
                if !status.recovery_required && status.transfers_configured && key == b'd' {
                    transfer_menu::run(&mut terminal)?;
                    return Ok(());
                }
                if !status.recovery_required && matches!(key, b'\r' | b'\n') {
                    requested_new = enter_console(&mut terminal)?;
                }
                if key == b'c' {
                    busy(&mut terminal, "Chiusura della sessione")?;
                    control::request("close", None, &[])?;
                }
                if key == b'f' {
                    terminal.flush_input();
                    terminal.write(&format!("{CLEAR}{FEEDBACK} Chiusura forzata: possibile perdita delle ultime modifiche.\r\n Premi F di nuovo per confermare; altro tasto annulla.{RESET}"))?;
                    if terminal.input(-1)?.as_slice().eq_ignore_ascii_case(b"f") {
                        busy(&mut terminal, "Chiusura forzata")?;
                        control::request("force-close", None, &[])?;
                        if status.recovery_required {
                            control::request("lock", None, &[])?;
                        }
                    }
                }
                return Ok(());
            }
            if !status.general_present
                && status.general_incomplete
                && !status.general_open
                && key == b'd'
            {
                if confirm_discard(&mut terminal, "preparazione generale incompleta")? {
                    busy(&mut terminal, "Eliminazione del tentativo incompleto")?;
                    control::request("discard-general-pending", None, &[])?;
                }
                return Ok(());
            }
            if !status.general_mounted {
                return Ok(());
            }
            if key == b'r' {
                transport_menu(&mut terminal)?;
                return Ok(());
            }
            if key == b'w' {
                network_menu(
                    &mut terminal,
                    if incomplete {
                        None
                    } else {
                        sessions.get(selected).map(String::as_str)
                    },
                )?;
                return Ok(());
            }
            if key == b'g' {
                key_menu(&mut terminal, false)?;
                return Ok(());
            }
            if status.general_readonly {
                if matches!(key, b'n' | b'\r' | b'\n') {
                    if status.api_keys.as_ref().is_some_and(|keys| {
                        keys.entries.len() > 1
                            || (status.gateway_state.is_some() && keys.selected.is_none())
                    }) && !key_menu(&mut terminal, true)?
                    {
                        return Ok(());
                    }
                    busy(&mut terminal, "Preparazione della sessione effimera in RAM")?;
                    control::request("open-ephemeral", None, &[])?;
                    requested_new = enter_console(&mut terminal)?;
                }
                return Ok(());
            }
            if key == b'a' {
                let temporary = status.api_keys.as_ref().is_some_and(|keys| {
                    keys.entries
                        .iter()
                        .any(|entry| entry.temporary && keys.selected.as_ref() == Some(&entry.id))
                });
                if let Some(secret) = terminal.password(if temporary {
                    "API key Abliteration - solo RAM fino al blocco"
                } else {
                    "API key Abliteration - salvata nel volume generale cifrato"
                })? {
                    busy(&mut terminal, "Salvataggio della API key")?;
                    control::request("set-api-key", None, &secret)?;
                }
                return Ok(());
            }
            if key == b'x' && status.api_key_present == Some(true) {
                terminal.flush_input();
                terminal.write(&format!("{CLEAR} Rimuovere la API key salvata?\r\n Premi X di nuovo per confermare; altro tasto annulla."))?;
                if terminal.input(-1)?.as_slice().eq_ignore_ascii_case(b"x") {
                    busy(&mut terminal, "Rimozione della API key")?;
                    control::request("clear-api-key", None, &[])?;
                }
                return Ok(());
            }
            if key == b'i' {
                incomplete = !incomplete;
                selected = 0;
                return Ok(());
            }
            if incomplete {
                if key == b'd' {
                    if let Some(id) = sessions.get(selected) {
                        if confirm_discard(
                            &mut terminal,
                            &format!("creazione interrotta {}", &id[..8]),
                        )? {
                            busy(&mut terminal, "Eliminazione del tentativo incompleto")?;
                            control::request("discard-session-pending", Some(id), &[])?;
                        }
                    }
                }
                return Ok(());
            }
            let id = if key == b'n' {
                None
            } else if matches!(key, b'\r' | b'\n') {
                status.sessions.get(selected).map(String::as_str)
            } else {
                return Ok(());
            };
            if key != b'n' && id.is_none() {
                return Ok(());
            }
            if status
                .api_keys
                .as_ref()
                .is_some_and(|keys| keys.entries.len() > 1)
                && !key_menu(&mut terminal, true)?
            {
                return Ok(());
            }
            let Some(secret) = (if id.is_some() {
                terminal.password("Password della sessione")?
            } else {
                new_password(
                    &mut terminal,
                    "Nuova sessione - password di almeno 16 byte",
                    "Ripeti la password della nuova sessione",
                )?
            }) else {
                return Ok(());
            };
            let id = if let Some(id) = id {
                id.to_owned()
            } else {
                busy(&mut terminal, "Creazione del volume cifrato")?;
                control::request("create", None, &secret)?.trim().to_owned()
            };
            busy(&mut terminal, "Apertura della VM della sessione")?;
            control::request("open", Some(&id), &secret)?;
            drop(secret);
            requested_new = enter_console(&mut terminal)?;
            Ok(())
        })();
        if let Err(error) = result {
            notice = match error.to_string().as_str() {
                "usb_selection_changed" => "La USB è cambiata. Controlla il supporto e ripeti la selezione.",
                "usb_command_failed" | "usb_partition_unavailable" | "usb_publish_failed" => "Preparazione USB non completata. Controlla lo stato; non rimuovere il supporto durante le operazioni.",
                "network_profile_empty" => "Nessuna rete da salvare. Configurala con Alt+F2 e riprova.",
                "network_profile_invalid" | "unsafe_file" => "Profilo non sicuro o non valido. Il salvataggio non è completato.",
                "network_profile_reload_failed" => "Impossibile ripristinare la rete. Blocca il generale e riprova, oppure configura la rete con Alt+F2.",
                "passwords_do_not_match" => "Le password non coincidono.",
                "password_too_short" => "Usa almeno 16 byte per la nuova password.",
                "invalid_key_name" => "Nome non valido: da 1 a 64 byte, senza caratteri di controllo o spazi ai bordi.",
                "api_key_missing" => "Seleziona una chiave API salvata prima di aprire la sessione.",
                "too_many_api_keys" => "Archivio pieno: sono consentite al massimo 64 chiavi.",
                "invalid_api_key" => {
                    "API key non valida: usa da 16 a 1024 caratteri ASCII senza spazi."
                }
                "gateway_start_failed" => {
                    "Gateway non disponibile. Il generale resta aperto: puoi bloccarlo e riprovare."
                }
                "gateway_unavailable" => "Gateway non attivo. Blocca il generale e sbloccalo prima di aprire una sessione.",
                "gateway_not_ready" => "Il percorso di rete non è ancora pronto. Attendi e riprova ad aprire la sessione.",
                "gateway_shutdown_unconfirmed" => "Chiusura non confermata. Il gateway è fermo: blocca di nuovo per chiudere il generale.",
                "invalid_proxy_endpoint" => "Proxy non valido: indica un IPv4 e una porta; loopback e rete interna non sono ammessi.",
                "invalid_proxy_authentication" => "Username e password SOCKS devono contenere da 1 a 255 byte, senza caratteri di controllo.",
                "external_proxy_requires_network" => "La rete è disabilitata in questa immagine: il proxy esterno non può essere attivato.",
                "invalid_destination" | "invalid_destination_port" | "invalid_destination_pattern" | "reserved_destination" => "Destinazione non valida: usa un dominio pubblico (anche *.example.com), un IP pubblico e una porta da 1 a 65535.",
                "too_many_network_rules" => "Sono ammesse al massimo 128 regole web.",
                "network_rule_missing" => "La regola non esiste più. Riapri il menu delle regole web.",
                "export_outcome_unknown" => "Export interrotto senza conferma di smontaggio. La USB può contenere una copia completa o parziale; non è stata confermata la rimozione sicura.",
                "transfer_outcome_unknown" => "Importazione interrotta senza conferma finale. Una copia già completata può essere presente nei documenti della sessione.",
                "session_must_be_closed" => "Chiudi la sessione prima di cambiare chiave o percorso di rete.",
                "session_channel_failed" | "invalid_session_ready" => "La sessione non ha completato l'avvio protetto. Chiudila prima di riprovare.",
                "insufficient_space" if status.general_readonly => {
                    "RAM insufficiente per il disco della sessione. Blocca per eliminare la preparazione incompleta."
                }
                "image_exists_or_unavailable" if status.general_readonly => {
                    "Preparazione effimera non disponibile. Blocca per completare la pulizia prima di riprovare."
                }
                "insufficient_space" => {
                    "Spazio insufficiente. Controlla le creazioni interrotte prima di riprovare."
                }
                _ => "Operazione non completata. Verifica lo stato mostrato prima di continuare.",
            }
            .to_owned();
        } else if key == b'q' {
            return Ok(());
        }
        terminal.flush_input();
    }
}

fn new_password(
    terminal: &mut Terminal,
    title: &str,
    repeat: &str,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let Some(secret) = terminal.password(title)? else {
        return Ok(None);
    };
    if secret.len() < 16 {
        return Err("password_too_short".into());
    }
    let Some(confirmation) = terminal.password(repeat)? else {
        return Ok(None);
    };
    if *secret != *confirmation {
        return Err("passwords_do_not_match".into());
    }
    Ok(Some(secret))
}

fn confirm_discard(terminal: &mut Terminal, label: &str) -> Result<bool> {
    terminal.flush_input();
    terminal.write(&format!("{CLEAR}{FEEDBACK} Elimina {label}?\r\n Questa operazione non si puo' annullare.\r\n Premi D di nuovo per confermare; altro tasto annulla.{RESET}"))?;
    Ok(terminal.input(-1)?.as_slice().eq_ignore_ascii_case(b"d"))
}

fn busy(terminal: &mut Terminal, message: &str) -> Result<()> {
    terminal.write(&format!(
        "{CLEAR}{BRAND} OBLIVION - controllo fidato{RESET}\r\n\r\n {message}..."
    ))
}

fn enter_console(terminal: &mut Terminal) -> Result<bool> {
    let result = terminal::bridge(terminal, control::console()?, |terminal| {
        transfer_menu::run(terminal)?;
        let status: Status = serde_json::from_str(&control::request("status", None, &[])?)?;
        Ok(status.session_open)
    });
    busy(terminal, "Chiusura della sessione")?;
    control::request("close", None, &[])?;
    Ok(result? == terminal::Action::New)
}

fn transport_label(transport: &Metadata) -> String {
    match transport {
        Metadata::Tor {} => "Tor".to_owned(),
        Metadata::Socks5 {
            endpoint,
            authenticated,
        } => format!(
            "SOCKS5 {endpoint}{}",
            if *authenticated { " con password" } else { "" }
        ),
    }
}

fn transport_menu(terminal: &mut Terminal) -> Result<()> {
    let status: Status = serde_json::from_str(&control::request("status", None, &[])?)?;
    let egress = status.egress.ok_or("general_not_open")?;
    terminal.flush_input();
    terminal.write(&format!("{CLEAR}{BRAND} OBLIVION - percorso di rete{RESET}\r\n\r\n Attuale: {}{}\r\n Salvato: {}\r\n\r\n [T] Tor  [S] SOCKS5  [P] Usa profilo salvato\r\n [Esc] Indietro\r\n\r\n Il cambio chiude il gateway precedente.\r\n Nessuna connessione diretta o cambio automatico.\r\n {}",
        transport_label(&egress.selected), if egress.temporary { " (fino al blocco del generale)" } else { "" },
        transport_label(&egress.saved), if status.general_readonly { "Profilo in sola lettura: modifiche solo in RAM." } else { "" }))?;
    let key = terminal.input(-1)?;
    let transport = match key.as_slice() {
        b"p" | b"P" => {
            busy(terminal, "Ripristino del percorso salvato")?;
            control::request("egress", None, br#"{"action":"saved"}"#)?;
            return Ok(());
        }
        b"t" | b"T" => Transport::default(),
        b"s" | b"S" => {
            let Some(transport) = proxy_settings(terminal)? else {
                return Ok(());
            };
            transport
        }
        _ => return Ok(()),
    };
    transport.validate()?;
    let save = if status.general_readonly {
        false
    } else {
        terminal.flush_input();
        terminal.write(&format!("{CLEAR} Percorso scelto: {}\r\n\r\n [S] Salva nel generale cifrato\r\n [T] Usa fino al blocco del generale\r\n [Esc] Annulla", transport_label(&transport.metadata())))?;
        match terminal.input(-1)?.as_slice() {
            b"s" | b"S" => true,
            b"t" | b"T" => false,
            _ => return Ok(()),
        }
    };
    let command = if save {
        egress::Command::Save { transport }
    } else {
        egress::Command::Select { transport }
    };
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&command)?);
    busy(terminal, "Cambio del percorso di rete")?;
    control::request("egress", None, &bytes)?;
    Ok(())
}

fn network_menu(terminal: &mut Terminal, session: Option<&str>) -> Result<()> {
    let mut selected = 0usize;
    loop {
        let status: Status = serde_json::from_str(&control::request("status", None, &[])?)?;
        let network = status.network_policy.ok_or("general_not_open")?;
        let rules = network.policy.rules();
        selected = selected.min(rules.len().saturating_sub(1));
        let mut view = format!(
            "{CLEAR}{BRAND} OBLIVION - regole web{RESET}\r\n\r\n {}\r\n Destinazioni senza regola: bloccate in attesa di autorizzazione.\r\n\r\n",
            if network.temporary {
                "Regole temporanee fino al blocco del generale."
            } else if network.enabled {
                "Regole salvate nel generale cifrato."
            } else {
                "Nessuna destinazione web autorizzata."
            }
        );
        let size = terminal.size();
        let limit = size.0.saturating_sub(13).max(1) as usize;
        for (index, rule) in rules
            .iter()
            .enumerate()
            .skip(selected.saturating_sub(limit - 1))
            .take(limit)
        {
            let label = format!(
                " {} {} {}:{} [{}]",
                if index == selected { ">" } else { " " },
                match rule.action() {
                    Action::Allow => "Consenti",
                    Action::Deny => "Blocca",
                    Action::Ask => "Chiedi",
                },
                rule.destination(),
                rule.port(),
                rule.session().map(|id| &id[..8]).unwrap_or("globale")
            );
            let width = size.1.saturating_sub(2) as usize;
            view.push_str(&label[..label.len().min(width)]);
            view.push_str(if label.len() > width { "~\r\n" } else { "\r\n" });
        }
        if rules.is_empty() {
            view.push_str(" Nessuna regola.\r\n");
        }
        view.push_str(&format!("\r\n {ACTION}[A] Aggiungi/modifica  [D] Rimuovi  [J/K] Seleziona\r\n [P] Usa regole salvate  [Esc] Indietro{RESET}\r\n Chiedi: bloccato; conferme interattive non ancora disponibili.\r\n"));
        terminal.flush_input();
        terminal.write(&view)?;
        let key = terminal.input(-1)?;
        let removing = match key.as_slice() {
            b"\x1b" => return Ok(()),
            b"j" | b"J" | b"\x1b[B" => {
                selected = (selected + 1).min(rules.len().saturating_sub(1));
                continue;
            }
            b"k" | b"K" | b"\x1b[A" => {
                selected = selected.saturating_sub(1);
                continue;
            }
            b"p" | b"P" => {
                control::request("network-policy", None, br#"{"action":"saved"}"#)?;
                continue;
            }
            b"a" | b"A" => false,
            b"d" | b"D" if !rules.is_empty() => true,
            _ => continue,
        };
        let rule = if removing {
            rules[selected].clone()
        } else {
            let Some(destination) =
                terminal.text("Dominio, *.dominio o IP pubblico - senza URL o porta")?
            else {
                continue;
            };
            let Some(port) = terminal.text("Porta di destinazione (esempio 443 per HTTPS)")? else {
                continue;
            };
            let port = port
                .parse::<u16>()
                .map_err(|_| "invalid_destination_port")?;
            terminal.flush_input();
            terminal.write(&format!("{CLEAR} Regola web\r\n\r\n [A] Consenti  [D] Blocca  [C] Chiedi (attualmente blocca)\r\n [Esc] Annulla"))?;
            let action = match terminal.input(-1)?.as_slice() {
                b"a" | b"A" => Action::Allow,
                b"d" | b"D" => Action::Deny,
                b"c" | b"C" => Action::Ask,
                _ => continue,
            };
            let scope = if let Some(id) = session {
                terminal.flush_input();
                terminal.write(&format!("{CLEAR} Ambito della regola\r\n\r\n [G] Tutte le sessioni\r\n [S] Solo sessione {}\r\n [Esc] Annulla", &id[..8]))?;
                match terminal.input(-1)?.as_slice() {
                    b"g" | b"G" => None,
                    b"s" | b"S" => Some(id.to_owned()),
                    _ => continue,
                }
            } else {
                None
            };
            Rule::new(destination, port, action, scope)?
        };
        terminal.flush_input();
        terminal.write(&format!("{CLEAR} {} regola {}:{} [{}]\r\n Azione: {}\r\n\r\n Autorizzare una destinazione permette ai tool di inviarle dati.\r\n Blocca prevale su Chiedi, che prevale su Consenti.\r\n\r\n {}[T] Applica fino al blocco del generale\r\n [Esc] Annulla",
            if removing { "Rimuovi" } else { "Imposta" }, rule.destination(), rule.port(), rule.session().unwrap_or("globale"),
            match rule.action() { Action::Allow => "Consenti", Action::Deny => "Blocca", Action::Ask => "Chiedi" },
            if status.general_readonly { "Profilo in sola lettura.\r\n " } else { "[S] Salva nel generale cifrato tutte le regole attuali\r\n " }))?;
        let save = match terminal.input(-1)?.as_slice() {
            b"s" | b"S" if !status.general_readonly => true,
            b"t" | b"T" => false,
            _ => continue,
        };
        let command = if removing {
            network::Command::Remove { rule, save }
        } else {
            network::Command::Put { rule, save }
        };
        control::request(
            "network-policy",
            None,
            &zeroize::Zeroizing::new(serde_json::to_vec(&command)?),
        )?;
    }
}

fn proxy_settings(terminal: &mut Terminal) -> Result<Option<Transport>> {
    let Some(endpoint) = terminal.text("Proxy SOCKS5 - IPv4:porta (esempio 192.168.1.20:1080)")?
    else {
        return Ok(None);
    };
    let endpoint = endpoint.parse().map_err(|_| "invalid_proxy_endpoint")?;
    terminal.flush_input();
    terminal.write(&format!("{CLEAR} Il proxy vede le destinazioni richieste.\r\n Username e password SOCKS viaggiano in chiaro fino al proxy.\r\n Le richieste API usano HTTPS verificato.\r\n\r\n [A] Con autenticazione  [N] Senza autenticazione\r\n [Esc] Annulla"))?;
    let authentication = match terminal.input(-1)?.as_slice() {
        b"a" | b"A" => {
            let Some(username) = terminal.password("Username SOCKS5 (nascosto)")? else {
                return Ok(None);
            };
            let Some(password) = terminal.password("Password SOCKS5")? else {
                return Ok(None);
            };
            Some(Authentication {
                username: zeroize::Zeroizing::new(std::str::from_utf8(&username)?.to_owned()),
                password: zeroize::Zeroizing::new(std::str::from_utf8(&password)?.to_owned()),
            })
        }
        b"n" | b"N" => None,
        _ => return Ok(None),
    };
    Ok(Some(Transport::Socks5 {
        endpoint,
        authentication,
    }))
}

fn key_menu(terminal: &mut Terminal, choosing: bool) -> Result<bool> {
    let mut selected = 0usize;
    loop {
        let status: Status = serde_json::from_str(&control::request("status", None, &[])?)?;
        let keys = status.api_keys.ok_or("general_not_open")?;
        selected = selected.min(keys.entries.len().saturating_sub(1));
        let mut view = format!("{CLEAR}{BRAND} OBLIVION - chiavi Abliteration{RESET}\r\n\r\n");
        if choosing {
            view.push_str(" Scegli la chiave per questa apertura.\r\n");
        }
        let limit = terminal.size().0.saturating_sub(10).max(1) as usize;
        for (index, entry) in keys
            .entries
            .iter()
            .enumerate()
            .skip(selected.saturating_sub(limit - 1))
            .take(limit)
        {
            view.push_str(&format!(
                " {} {}{}{}{}\r\n",
                if index == selected { ">" } else { " " },
                entry.name,
                if entry.temporary { " [RAM]" } else { "" },
                if keys.default.as_ref() == Some(&entry.id) {
                    " [predefinita]"
                } else {
                    ""
                },
                if keys.selected.as_ref() == Some(&entry.id) {
                    " [selezionata]"
                } else {
                    ""
                }
            ));
        }
        if keys.entries.is_empty() {
            view.push_str(" Nessuna chiave salvata.\r\n");
        }
        let entry = keys.entries.get(selected);
        view.push_str("\r\n [Invio] Usa  [J/K] Seleziona  [Esc] Indietro\r\n");
        view.push_str(" [T] Usa nuova chiave in RAM (fino al blocco)\r\n");
        if !status.general_readonly && !choosing {
            view.push_str(" [A] Aggiungi al generale cifrato\r\n");
            if !entry.is_some_and(|entry| entry.temporary) {
                view.push_str(" [D] Predefinita\r\n");
            }
        }
        if !choosing && (!status.general_readonly || entry.is_some_and(|entry| entry.temporary)) {
            view.push_str(" [R] Rinomina  [S] Sostituisci  [X] Rimuovi\r\n");
        }
        terminal.write(&view)?;
        let input = terminal.input(-1)?;
        let byte = match input.as_slice() {
            b"\x1b[A" => b'k',
            b"\x1b[B" => b'j',
            [byte] => byte.to_ascii_lowercase(),
            _ => continue,
        };
        if byte == 27 {
            return Ok(false);
        }
        if byte == b'j' {
            selected = (selected + 1).min(keys.entries.len().saturating_sub(1));
            continue;
        }
        if byte == b'k' {
            selected = selected.saturating_sub(1);
            continue;
        }
        let command = if byte == b't' {
            let Some(name) = terminal.name("Nome della chiave temporanea (massimo 64 byte)")?
            else {
                continue;
            };
            let Some(bytes) =
                terminal.password("API key Abliteration - solo RAM fino al blocco")?
            else {
                continue;
            };
            keys::Command::Temporary {
                name,
                key: zeroize::Zeroizing::new(std::str::from_utf8(&bytes)?.to_owned()),
            }
        } else if matches!(byte, b'\r' | b'\n') {
            let Some(entry) = entry else {
                continue;
            };
            keys::Command::Select {
                id: entry.id.clone(),
            }
        } else {
            if choosing {
                continue;
            }
            if byte == b'a' {
                if status.general_readonly {
                    continue;
                }
                let Some(name) = terminal.name("Nome della nuova chiave (massimo 64 byte)")? else {
                    continue;
                };
                let Some(bytes) = terminal
                    .password("API key Abliteration - salvata nel volume generale cifrato")?
                else {
                    continue;
                };
                keys::Command::Add {
                    name,
                    key: zeroize::Zeroizing::new(std::str::from_utf8(&bytes)?.to_owned()),
                }
            } else {
                let Some(entry) = entry else {
                    continue;
                };
                if status.general_readonly && !entry.temporary {
                    continue;
                }
                match byte {
                    b'r' => {
                        let Some(name) = terminal.name("Nuovo nome della chiave")? else {
                            continue;
                        };
                        keys::Command::Rename {
                            id: entry.id.clone(),
                            name,
                        }
                    }
                    b's' => {
                        let Some(bytes) =
                            terminal.password("Sostituisci la API key selezionata")?
                        else {
                            continue;
                        };
                        keys::Command::Replace {
                            id: entry.id.clone(),
                            key: zeroize::Zeroizing::new(std::str::from_utf8(&bytes)?.to_owned()),
                        }
                    }
                    b'd' if !entry.temporary => keys::Command::Default {
                        id: entry.id.clone(),
                    },
                    b'x' => {
                        terminal.flush_input();
                        terminal.write(&format!("{CLEAR} Rimuovere la chiave {}?\r\n Premi X di nuovo per confermare; altro tasto annulla.", entry.name))?;
                        if !terminal.input(-1)?.as_slice().eq_ignore_ascii_case(b"x") {
                            continue;
                        }
                        keys::Command::Remove {
                            id: entry.id.clone(),
                        }
                    }
                    _ => continue,
                }
            }
        };
        let selected = matches!(
            command,
            keys::Command::Select { .. } | keys::Command::Temporary { .. }
        );
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&command)?);
        busy(terminal, "Aggiornamento delle chiavi")?;
        control::request("api-keys", None, &bytes)?;
        if selected {
            return Ok(true);
        }
    }
}
