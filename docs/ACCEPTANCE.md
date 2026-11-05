# Collaudo di Oblivion 1.0

La [roadmap](oblivion1.0-roadmap.md) descrive cosa entra nella 1.0. Questa lista specifica come verificarlo. Il [registro tecnico](STATUS.md) conserva le prove precedenti su codice, fixture e VM.

Le prove **Browser** usano il binario Oblivion installato e le TUI native dentro un terminale del browser collegato al runtime reale. Le prove **Desktop**, **CLI**, **Lab** e **Live** richiedono le superfici indicate nella tabella. Un esito vale per il flusso, la build e la piattaforma registrati.

Per ogni prova annotare ID, data, build, piattaforma, superficie, esito (`Pass`, `Parziale`, `Fallito`, `Bloccato`), risultato osservato ed eventuale riferimento al commit della correzione. Le righe senza un esito nel registro restano da eseguire per la candidata. Dopo un fix, ripetere il caso sulla nuova build e aggiungere un esito.

Usare archivi e dischi separati dai dati personali, file sintetici e due runtime distinti per i ripristini. Eseguire crash, saturazione, interruzioni e `runtime atomic` solo in ambienti di test dedicati. Inserire le credenziali di prova nel client nativo quando richiesto e tenere password, token, codici di accesso e contenuti reali fuori da evidenze, log e commit.

## 1. Avvio, archivio e Safes

| ID | Superficie | Prova ed esito atteso |
| --- | --- | --- |
| UI-01 | Browser, Desktop, Live | Da runtime fermo aprire `oblivion`. Verificare avvio, errori e `R` per riprovare. Aprire Safes con `F1`, Settings con `F2` dopo lo sblocco e System con `F3`. Dati di sistema leggibili e comandi indisponibili spiegati. Su Live verificare il logo una volta per avvio. |
| UI-02 | Browser, Desktop, Live | Navigare con frecce, `Tab`, `Enter`, `Esc` e, dove supportato, mouse. Ridimensionare a 80×24 e 160×50. Focus, selezione, titoli, azioni e messaggi restano leggibili. Verificare layout tastiera non US, Unicode e incolla esplicito. |
| STO-01 | Browser, CLI | Creare l'archivio da storage nuovo. Rivedere posizione/capacità, annullare, provare spazio insufficiente e ripetere dopo interruzione. `init --reset-incomplete` rimuove solo la preparazione incompleta. Lo storage appena pubblicato resta bloccato. |
| STO-02 | Browser, CLI | Sbloccare con password errata e corretta. `unlock --read-only` permette l'accesso consentito e rifiuta le mutazioni. Verificare `safes`, `status --json`, `lock`, `Ctrl+Q`, `Esc` e la conferma di uscita. Dopo il lock il catalogo privato sparisce e i processi Safe terminano. |
| STO-03 | Browser, CLI, Lab, Live | Entrare in Ephemeral mode, creare Safes, scrivere un canary, chiudere, riavviare e confrontare il catalogo e l'hash del supporto persistente. Le Safes RAM spariscono e il supporto resta invariato. Ripetere con memoria insufficiente e archivio persistente già aperto. |
| SAFE-01 | Browser, CLI | Creare una Safe nominata (`N`), provarne un nome non valido, aprire `D` Details, rinominare, chiudere e aumentare la capacità da Settings. Identità e file restano uguali. Verificare `safe open/rename/grow`, limite capacità e rifiuto del resize a Safe aperta. |
| SAFE-02 | Browser, CLI, Lab | Aprire due agent nella stessa Safe e due Safes distinte, anche in parallelo. La stessa Safe condivide il workspace. Le altre restano isolate. `L` o `close SAFE` chiude solo la Safe selezionata. Provare rilascio dell'ultimo client, riuso slot, richieste concorrenti e riapertura. |
| SAFE-03 | Browser, CLI, Lab | Scrivere un file, installare una dipendenza con `sudo`, chiudere, riaprire e fare tre riavvii del runtime. File, permessi e installazione restano nella Safe originaria. Ripetere con volume pieno, arresto durante il lavoro e recupero dopo crash. |
| SAFE-04 | Browser, CLI, Lab | Da Settings impostare timer Safe e host, provare valori invalidi e `0`, poi misurare entrambe le scadenze. Solo input umano aggiorna l'attività. Output del client e trasferimenti non tengono aperta la Safe. Verificare la chiusura e i messaggi durante un teardown incerto. |

## 2. Agent e Workspace

| ID | Superficie | Prova ed esito atteso |
| --- | --- | --- |
| AG-01 | Browser, Desktop | Aprire Codex, Claude Code e OpenCode 2 dal manager e con `oblivion run`. Appare la TUI nativa del client scelto, con topbar Safe/agent e footer `F7 Files` e `F9 Network` su righe riservate. Provare i ridisegni, lo scroll e il resize anche durante lo streaming. |
| AG-02 | Browser, Desktop | Da ogni agent e da Workspace aprire `F7` e `F9`, poi tornare con `Esc`. Il terminale recupera contenuto, cursore e focus. Un comando sintetico in corso continua. Provare cambi ripetuti, input accodato e chiusura tab o terminale durante un pannello. |
| AG-03 | Browser, Provider | Per ciascun agent provare login nativo o API key supportata, chiave invalida, risposta in streaming, uso di un tool sui file della Safe e stop. Provare scadenza e logout con account di test. Separare accesso provider da disponibilità del trasporto. OpenCode 2 include una prova `abliteration-ai`. [Provider](PROVIDERS.md) |
| AG-04 | Browser, CLI, Provider | Creare più chat nello stesso workspace, riaprire con `C` Continue latest e con i comandi nativi, poi ripetere dopo riavvio e chiusura durante streaming. Verificare identità della chat e ultimo stato salvato. Ogni client mostra le proprie chat. |
| AG-05 | CLI, Desktop, Lab | Provare `run --name`, `--safe`, `--ephemeral`, route e policy prima del nome dell'agent e argomenti nativi dopo. Eseguire `--version`, output in pipe, input rediretto e segnali. Byte, exit code e argomenti corrispondono al client. Safe inesistente e flag incompatibili danno errore prima di creare dati. |
| AG-06 | Browser, CLI, Desktop | Avviare `W` Workspace o `shell --safe`, provare tmux con `Ctrl+B`, nuovi pannelli, shell, resize e uscita. Verificare condivisione del workspace nella stessa Safe, policy Offline opzionale e persistenza delle modifiche. |
| AG-07 | Lab, Desktop | Far produrre al guest sequenze di controllo per titolo, clipboard, mouse e interrogazioni sul terminale. L'host applica le proprie regole, la TUI riceve coordinate del suo spazio e l'incolla esplicito rimane utilizzabile. La sessione restituisce il terminale in condizioni normali dopo uscita e crash. |

## 3. Network

| ID | Superficie | Prova ed esito atteso |
| --- | --- | --- |
| NET-01 | Browser, CLI | `F9` su Safe chiusa propone l'apertura offline. Su Safe aperta provare Open Internet, Strict e Offline, `T` per scegliere route, `R` per aggiornare. Verificare policy corrente, stato di link e marcatori Tor/SOCKS5 solo con osservazione valida. |
| NET-02 | Browser, CLI, Lab | Usare Tor di default, SOCKS5 con DNS remoto, username opzionale e password nel prompt privato. Provare indirizzo malformato, autenticazione errata e proxy irraggiungibile. Verificare `proxy add/list/remove`, selezione `--proxy-profile` e assenza di password in metadati e argomenti registrati. |
| NET-03 | Lab, Provider | Catturare rete host e guest con traffico sintetico. Verificare TCP pubblico e FTP passivo in Open Internet, soli host ammessi in Strict, blocco in Offline. Tentare TCP diretto, DNS, UDP, IP privati, redirect e bypass con `sudo`. Il traffico ammesso usa il trasporto configurato e i tentativi di bypass non escono. |
| NET-04 | Browser, Lab | Cambiare route, invocare `tor_rotate` durante una richiesta e ripetere con bootstrap lento, proxy spento e rotazione fallita. La Safe interessata interrompe gli stream, riapre solo dopo verifica e resta bloccata in caso di errore. Un'altra Safe continua. |
| NET-05 | Browser, Lab | Osservare scadenza stato dopo dieci secondi, lock, riapertura con stesso ID e slot riusato. Un'osservazione precedente non autorizza un marcatore positivo. Provare certificato invalido, provider che rifiuta Tor, telemetria nota e aggiornamenti disabilitati. |

## 4. Files, supporti e trasferimenti

| ID | Superficie | Prova ed esito atteso |
| --- | --- | --- |
| FILE-01 | Browser, CLI | Da Files navigare `workspace` e `imports`, directory grandi e più pagine. Selezionare più voci da directory diverse e rivedere il basket. Provare percorso digitato/incollato, `file://` locale, spazi, Unicode e sequenze terminali. Le radici consentite restano il limite. |
| FILE-02 | Browser, CLI | Importare un file e una raccolta in una Safe, esportare con `files list/import/export` o i corrispettivi pannelli. Verificare manifest, mappatura dei nomi, progressi, conferma ed hash sui due lati. Provare annullamento prima dell'approvazione, uso in parallelo a una chat e copia CLI esplicita con `--yes`. |
| FILE-03 | Browser, CLI, Lab | Provare collisione di nomi, selezioni sovrapposte, link, file speciale, sorgente cambiata, spazio esaurito e disconnessione durante una copia. Nessuna sovrascrittura o pubblicazione parziale. Il risultato incerto rimanda allo stato verificabile. |
| FILE-04 | Browser, CLI, Lab | Da Transfer records e con `files transfers/status/recover/discard` ritrovare i record dopo riavvio o remount. Recovery pubblica solo staging verificato. Discard conserva dati pubblicati e modifiche successive. Cambio Safe, lock e destinazione diversa revocano o rifiutano l'operazione. |
| FILE-05 | Desktop | Aprire Desktop picker con `D`, usare dialogo e drag and drop su AppKit, Win32 e GTK. Rivedere la selezione prima della copia. Provare annullamento, chiusura di Files, lock e cambio apertura mentre la finestra è aperta. |
| FILE-06 | Live, CLI | In System e con `runtime live-media --json` verificare inventario, identità e refresh USB. Importare in sola lettura da un supporto separato. Esportare dopo approvazione e verificare hash, ricevuta, flush e rimozione. Ripetere con ext4, FAT, exFAT, unplug e interruzione. Verificare `files transfers/status/recover/discard --usb` dopo riavvio. [Live](LIVE.md) |

## 5. Backup, Share, famiglie e task

| ID | Superficie | Prova ed esito atteso |
| --- | --- | --- |
| BAK-01 | Browser, CLI, Lab | Da Settings → Personal backups esportare una Safe chiusa e ripristinarla su un'altra installazione. `backup export/import` preservano ID, password, file, chat nativa, installazioni e login salvati. Il ripristino parte Offline. La stessa identità già presente non viene sostituita. |
| BAK-02 | Browser, CLI, Lab | Provare backup alterato, password errata, destinazione occupata, stop durante copia e riavvio. Consultare history e `backup status`; `finish` completa una copia verificata senza ricopiarla e `discard` tocca solo staging incompleto. |
| SHARE-01 | Browser, CLI | Da `S` esportare una Safe e un ramo; da Settings → Share all esportare tutte. Provare filtri per file e chat, anteprima dei titoli, esclusioni, dipendenze di file/chat e opzione timer. Manifest e digest corrispondono alla selezione approvata. Una Safe inclusa e aperta impedisce l'export. |
| SHARE-02 | Browser, CLI, Lab | Da `I` Import Share e `share import` importare in un'altra installazione. Verificare nuove identità, relazioni, contenuti inclusi, ripresa nello stesso agent e assenza degli store di login. Timer applicati solo su consenso. Provare conflitto di nome, password errata, pacchetto alterato, copia interrotta, elenco e `share discard` di staging non pubblicato. |
| SHARE-03 | Lab | Misurare trasferimento via OnionShare su Tor pubblico con file sintetici, anche grandi. Verificare capacità, esito e hash; mantenere la qualifica di questo canale separata dalla copia Share locale. |
| FAM-01 | Browser, CLI, Lab | Da Settings → Family passwords rivedere tutti i membri, cambiare la password con le Safes chiuse e provare quella vecchia e quella nuova. Interrompere tra due membri e provare `safe password status`, `recover --complete` e `--rollback`. Verificare apertura indipendente di una figlia e la password originale dei backup già esistenti. |
| TASK-01 | Browser, Provider, Lab | Chiamare MCP `safe_status`, `chat_create` e `safe_create` da un agent. Verificare chat nel workspace scelto, figlia e nipote con volumi/gateway propri, provenienza nel manager, autorità circoscritta, limiti, teardown del ramo e indipendenza delle Safes estranee. |
| TASK-02 | Browser, CLI, Provider | Da `D` Details rivedere il task offline e aprire il client senza reinviarlo. Provare `safe task status/review/start/retry/cancel`, dettagli e ripresa nativa. Credenziale delegabile avvia la figlia dopo verifica della rete; credenziale assente o non supportata mostra needs-auth. |
| TASK-03 | Lab, Browser | Interrompere durante creazione, job, chiusura e auto-lock. Controllare esiti incerti, retry con richiesta vincolata, annullamento verificato e protezione dei task durante recupero e backup. Il retry non duplica un lavoro il cui esito non è stato riconciliato. |

## 6. Runtime, piattaforme e release

| ID | Superficie | Prova ed esito atteso |
| --- | --- | --- |
| RUN-01 | CLI, Lab | Verificare `--help`, `--version`, comando sconosciuto e help per profilo. Con `runtime start/stop/recover` provare avvio/stop concorrenti, client perso, timeout, controller occupato e riuso da un altro launcher. Un arresto incerto blocca nuove ammissioni finché verificato. |
| RUN-02 | CLI, Desktop, Lab | Su standalone provare `runtime install-bundle`, `update`, `gc`, `uninstall`, reinstallazione e `runtime atomic`. Coprire anche `install/deploy` dove esposti. Update e reinstallazione conservano l'identità e il disco; GC tocca solo release verificate. Atomic richiede runtime fermo e conferma e rimuove solo l'installazione di test. Provare annullamento, errore di checksum e ripresa interrotta. |
| PLAT-01 | Mac reale | Apple Silicon, avvio headless Apple VZ, KVM annidato, avvii ripetuti e qualifica del kernel della candidata. Ripetere su terminale reale e browser. Accertare che l'assenza dei prerequisiti dia un errore prima di allocare dati persistenti. |
| PLAT-02 | Linux reale | amd64 e arm64 con QEMU/KVM. Verificare installazione APT, Polkit con consenso, package upgrade durante runtime attivo, rimozione/reinstallazione e isolamento del socket tra utenti. Usare build della candidata. |
| PLAT-03 | Windows reale | x64 con Hyper-V. Provare macchina pulita, UAC stesso account/altro account, abilitazione e riavvio, ripresa del setup, VHDX/ACL, PATH, Windows Terminal, Ctrl+Q e F7/F9, picker, update/uninstall/atomic. Provare arresti forzati e assenza di Hyper-V o nested virtualization. |
| PLAT-04 | Live fisico | ISO amd64/arm64, avvio USB, console Debian per tastiera/fuso/rete e selezione del backing con `runtime choose-storage`. Verificare partizione dedicata, poco spazio, tre riavvii, distacco corrente e recupero con file/chat. Controllare i dischi interni e ripetere in RAM-only. |
| REL-01 | Lab, Desktop, Live | Cercare canary sintetici di chat, credenziali, file e tool dopo lock/crash in log, cache, temp, immagini, dump, swap, snapshot e artefatti dell'hypervisor sotto controllo della build. Verificare revoca di volumi, canali e gateway e separare la cronologia del terminale e i dati dell'OS host. |
| REL-02 | CI, Lab, Desktop, Live | Test dei pacchetti e `bun run check`, build accoppiate di controller/launcher e ISO amd64/arm64. Verificare versione, hash, inventario, provenienza/firma e licenze degli agent distribuiti. Provare gli artefatti installabili stessi. Le verifiche solo compilate e le prove su build diagnostica restano distinte dalla qualifica di release. |

## Registro degli esiti

| Data e build | Superficie | ID ed esito | Osservazione |
| --- | --- | --- | --- |
| 5 novembre 2026 · Mac ARM64 `1.0.0~dev20261105143801mac612chrome.5eVYY0eu`, controller diagnostico Debian 6.12 | Browser, runtime installato | AG-01 `Parziale` · AG-02 `Parziale` | Codex, Claude Code e OpenCode 2 hanno mostrato la TUI nativa con entrambe le barre. Verificati ritorno da Network in Codex e Claude, ritorno da Files e scrittura senza invio in OpenCode. Claude ha mostrato il setup iniziale in una Safe con Tor. Autenticazione, streaming, resize durante risposta e tutti i pannelli per ogni agent restano da verificare. |
| 5 novembre 2026 · sviluppo Mac, controller diagnostico Debian 6.12 | CLI e laboratorio | SAFE-02 `Parziale` · SAFE-03 `Parziale` · SAFE-04 `Parziale` · BAK-01 `Parziale` | Prove headless precedenti su Safes concorrenti, persistenza del riferimento OpenCode e di un file, timer Safe e ripristino del volume in un secondo archivio. Dettagli ed estensione delle prove nel [registro tecnico](STATUS.md). |
