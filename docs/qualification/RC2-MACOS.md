# RC2 — collaudo macOS Apple Silicon

Registro del 12 novembre 2026. **La piattaforma non è ancora qualificata.**
Le prove qui descritte eseguono i binari del bundle RC2 e il controller
distribuito, con due archivi nuovi e sintetici. Il deploy usa percorsi separati
nell'account macOS corrente: non equivale all'installazione da un account pulito
né al collaudo dell'installer CLI scaricato con le protezioni macOS predefinite.

**Profilo scelto il 12 novembre 2026:** la prima distribuzione Mac è CLI, con
bootstrap `curl | bash`. Developer ID e notarizzazione non sono un requisito
obbligatorio per chiudere questo profilo; restano un'opzione per una successiva
distribuzione firmata/notarizzata. Occorre comunque provare il download,
l'installazione e l'avvio su account pulito, senza disattivare Gatekeeper o
rimuovere automaticamente la quarantena. Questa scelta non garantisce
l'accettazione su ogni Mac o sotto ogni policy amministrata.

## Candidata ed evidenze

| Identità | Valore |
| --- | --- |
| Tag | `v1.0.0-rc.2` |
| Commit | `eb6f97a1b2e56ba6494d0f03c35c530666605af3` |
| Versione / canale / formato | `1.0.0~rc2` / `rc` / manifest v2 |
| Target | `darwin-arm64`, Apple Virtualization.framework |
| Host osservato | Apple M4 Pro, 24 GiB, macOS 15.7.3 (`24G419`), arm64 |
| Archivio | `oblivion-1.0.0-rc2-darwin-arm64.tar` |
| SHA-256 archivio | `ffc679dc655c7571e19f0ed3f3076cd8c12b18275947844098f048efc2d25378` |
| Bundle ID | `571fd4b15ea1f473c11bcf77bd449e4c241b35a2f73c4425cf479420771373a8` |
| Inventario | 37 file verificati |

La [CI del sorgente](https://github.com/exploita-ai/oblivion/actions/runs/43124658498)
ha completato 9 job su 9. Le build RC2 di
[desktop nativo](https://github.com/exploita-ai/oblivion/actions/runs/43125394825),
[Debian desktop](https://github.com/exploita-ai/oblivion/actions/runs/43125398262)
e [Live](https://github.com/exploita-ai/oblivion/actions/runs/43125395225)
hanno completato gli 11 job previsti e caricato 18 asset nella bozza prerelease.
Questo registra la produzione e la consegna; non qualifica gli altri target.

I risultati locali stanno in
[`artifacts/qualification/rc2-macos/evidence/`](../../artifacts/qualification/rc2-macos/evidence/),
directory ignorata da Git. `inventory.json` registra identità, inventario e
verifiche dei binari; `cli-results.jsonl` associa comando, esito, durata e
SHA-256 del log alle 78 invocazioni CLI, inclusi rifiuti attesi e tentativi
esplorativi non riusciti. I 78 log indicizzati sono conservati con nomi univoci
e i loro digest sono stati verificati. Il digest dell'indice congelato è
`85ac457862b29f4366a3e2fdec123a8d81652cd59f6e6e08c1d89c92cd522438`;
quello di `inventory.json` è
`b6369089ce59d82ce18cd2ac66be771ceaa6350ebe593414ec1e6ab1fe8d19d2`.
I file non sono pubblicati con questo documento:
contengono dettagli del runtime QA e vanno conservati separatamente. Il presente
registro riporta soltanto risultati sintetici, senza password, token o dati
personali. La retention a lungo termine delle evidenze di qualifica resta da
completare.

## Superficie di prova

`OBLIVION_RUNTIME_DIRECTORY` e `XDG_DATA_HOME` selezionano runtime e prefisso
software QA separati. `runtime deploy` attiva il bundle verificato; il comando
globale dell'account non viene sostituito. Si usa la CLI dello stesso bundle
per l'intera sequenza. Il helper riporta `virtualization`, `nested` e
`supported` tutti `true` per `apple-vz`.

Il secondo runtime usa un proprio archivio nuovo per il ripristino del backup.
Entrambi i runtime QA completano il proprio `lock` e `runtime stop` al termine
delle rispettive prove.

Il controller conserva il profilo del bundle: 4 CPU, 6144 MiB e nuovo backing
sparse da 16 GiB. Non sono stati sovrapposti kernel, helper o worker diagnostici.
Le firme ad hoc dei componenti nativi passano la verifica locale `codesign`;
questo non attesta Developer ID, notarizzazione o approvazione Gatekeeper.

## Esiti registrati

Gli ID rinviano alla [matrice di accettazione](../ACCEPTANCE.md). `Parziale`
significa che sono riuscite le sotto-prove elencate, non l'intero scenario.

| ID / esito | Risultato osservato | Limite |
| --- | --- | --- |
| REL-02 · `Parziale` | SHA-256 del TAR, identità del bundle, inventario di 37 file, versione e verifica locale delle firme ad hoc coerenti. | Mancano provenienza completa, revisione delle licenze e collaudo dell'installer CLI finale con le protezioni del sistema attive. |
| RUN-01 / RUN-02 · `Parziale` | Help/versione disponibili; comando sconosciuto rifiutato. Deploy QA e avvio del controller distribuito riusciti; tre cicli espliciti di arresto e avvio completati. | Restano manutenzione da account pulito, guasti del ciclo runtime, reinstallazione e Atomic. Vedere anche il difetto di stop osservato sotto. |
| RUN-01 · `Fallito` nella concorrenza con auto-arresto | `runtime stop` restituisce EOF ed exit 1 durante l'auto-arresto, mentre il retry riesce. | Correzione e regressione verificate nel sorgente; il bundle RC2 non contiene il fix e serve una nuova candidata. |
| STO-01 · `Parziale` | `init` pubblica il nuovo archivio e lo lascia bloccato. `init --reset-incomplete` rifiuta l'archivio già pubblicato. | Restano annullamento, spazio insufficiente e interruzione del setup. |
| STO-02 · `Parziale` | Password sintetica errata rifiutata con `volume_unlock_failed`; il successivo sblocco corretto riesce. Sblocco readonly riuscito e rinomina rifiutata; lock riuscito. | Restano gli altri casi della matrice, incluso il percorso interattivo. |
| PLAT-01 / AG-05 · `Parziale` | Apple VZ avvia il controller RC2 e una Safe persistente Offline. I client ufficiali eseguono `--version` con exit 0: Codex `0.159.2`, Claude Code `2.1.302`, OpenCode `2.0.1`. | Non è un login provider, una prova della TUI o la qualifica completa di hardware e terminali. |
| SAFE-01 · `Parziale` | Rinomina Unicode riuscita; crescita CLI da 2048 a 2304 MiB in 26,448 s con la stessa Safe. Crescita a Safe aperta e dimensione invalida rifiutate. | Restano crescita dalla TUI, interruzioni e gli altri limiti della matrice. |
| FILE-01 / FILE-02 · `Parziale` | Import, elenco ed export del canary sintetico riusciti; i byte esportati coincidono con la sorgente. | Restano matrice di selezioni, UI/picker, copie concorrenti, guasti e recovery. |
| SAFE-03 · `Parziale` | Dopo ciascuno dei tre riavvii a freddo, l'archivio parte bloccato e lo sblocco riapre la stessa Safe; l'export conserva i 53 byte del canary. | Restano pacchetti installati, volume pieno, crash, recovery e percorsi interattivi della matrice. |
| BAK-01 · `Parziale` | Export del backup cifrato da 2304 MiB in 69,702 s e ripristino nel secondo archivio indipendente. La Safe conserva identità e password originale, parte chiusa senza recovery pendente e riapre Offline. Il canary esportato conserva i 53 byte originali. | Restano chat, login salvati, dipendenze installate, conflitti e gli altri casi della matrice. |
| BAK-02 · `Parziale` | Il primo import copia 2.415.919.104 byte ma non può richiedere la password senza terminale. Lo stato conserva la transazione inattiva `copied`; `backup finish` con PTY e password originale completa in 13,536 s senza ricopiare il payload. | È verificato questo recupero dopo mancato prompt, non tutta la matrice di alterazioni, interruzioni, conflitti e discard. |

Un secondo comando ha passato `--policy offline` a una Safe già aperta ed è
stato rifiutato: il cambio della rete di una Safe attiva appartiene ai controlli
Network. Questo tentativo non dimostra un guasto di avvio dell'agent.

Il file sorgente, il primo export, i tre export dopo riavvio e l'export dal
backup ripristinato hanno SHA-256
`be4ff4d17b78b7d06ce7d29ecfe6add1837b111f7195440d868b7accd9d12561`.

**RUN-01, difetto osservato:** durante una sequenza senza owner residente,
`runtime stop` ha ricevuto EOF mentre il runtime si arrestava automaticamente;
il comando è terminato con exit 1, mentre il retry è riuscito. I tre cicli
successivi con avvio residente esplicito sono riusciti, ma non cancellano quel
risultato. La correzione sorgente
`1d5cbb70ceda3f003bfe16c19b2e39e7c31eed30` ha una prova di regressione che
fallisce prima del fix e passa dopo. La verifica locale conta 40 test runtime
riusciti e due fixture subprocess invocate dai test proprietari. Il
[primo run CI](https://github.com/exploita-ai/oblivion/actions/runs/43203754047)
ha completato 8 job su 9: il controllo runtime passa, mentre una fixture del
listener Linux arm64 presumeva la chiusura immediata del descrittore anche
durante i fork concorrenti. Il test ora verifica subito la revoca di admission
e attende fino a due secondi il rifiuto della connessione, conservando le
verifiche di elezione e rimozione. La verifica portabile locale conta 11 test
riusciti; il nuovo sorgente richiede una CI completa prima dell'integrazione.
RC2 conserva i propri byte: la correzione deve
essere ricostruita e riprovata su una nuova candidata prima di chiudere il gate.

## Gate ancora aperti

1. Completare i flussi comuni sulla candidata esatta: setup e recovery,
   persistenza e RAM-only, Safes concorrenti, crescita e timer, Files con
   collisioni/interruzioni/recupero, terminale nativo e picker AppKit. Le
   correzioni precedenti di concorrenza e il timeout Files richiedono riprova.
2. Qualificare Tor/SOCKS5, Strict/Offline, rotazione e guasti con due Safes,
   catture e canary; attribuire la memoria a sistema, agent e Tor per verificare
   il budget. Un avvio Offline non copre queste prove.
3. Usare account o chiavi di collaudo inseriti nei tre client ufficiali per
   login, streaming, tool, annullamento, rinnovo/logout e resume dopo reboot.
   OpenCode 2 include `abliteration-ai`. Non importare credenziali personali
   dall'host e non includerle nelle evidenze.
4. Completare backup, Share, famiglie e task nei due archivi QA indipendenti,
   includendo chat sintetiche autentiche. Completare i flussi OnionShare
   nella CLI/manager correnti: il backend da solo non rende disponibile la
   funzionalità. Serve inoltre un destinatario indipendente su Tor pubblico.
5. Chiudere installazione CLI e manutenzione da account pulito, preflight su
   host non supportato, comportamento con le protezioni macOS predefinite,
   provenienza e licenze. Il [profilo di distribuzione](../MACOS-DISTRIBUTION.md)
   distingue il bootstrap CLI dalla firma e notarizzazione opzionali; nessun
   installer deve disattivare Gatekeeper o eliminare la quarantena.

Ogni modifica a sorgente, versione, firma o packaging produce una nuova
candidata e richiede le verifiche pertinenti sui nuovi digest. RC2 non viene
modificata in-place. La promozione a `main` e la pubblicazione stabile restano
subordinate ai gate comuni e a `PLAT-01`, secondo il
[piano di rilascio](../DEVELOPMENT.md#branch-integration-and-release-plan).
