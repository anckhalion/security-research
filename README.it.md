# sora-malvertising-analysis

**Analisi tecnica di una doppia infezione da malvertising a tema "Sora AI" (dicembre 2024 – gennaio 2025): un kit MaaS di falsi installer Electron con esecuzione fileless in Rust e un infostealer Python "Braodo-like" con esfiltrazione via Telegram.**

🇬🇧 [English version](README.md)

📄 Paper completo su Zenodo: [DOI da inserire] — [PDF + Markdown italiano](docs/paper_it.md) | [English PDF + Markdown](docs/paper_en.md)
📰 Articolo divulgativo su Substack: [link da inserire]

---

## ⚠️ Disclaimer

Questo repository è pubblicato **esclusivamente a scopo di ricerca e difesa** (sicurezza informatica, threat intelligence, formazione). Non contiene campioni di malware, eseguibili, script eseguibili né codice pronto all'uso offensivo. Gli indicatori di compromissione sono **defangati** secondo convenzione (`hxxp://`, `dominio[.]com`). L'autore non è responsabile di usi impropri delle informazioni qui pubblicate. Se gestisci un servizio citato (hosting, piattaforma), gli abuse contact sono indicati nel paper.

## TL;DR

Tra dicembre 2024 e gennaio 2025 una postazione Windows è stata infettata due volte da falsi software "Sora AI" promossi tramite annunci sui social:

| # | Data | Esca | Malware | Esito |
|---|---|---|---|---|
| A | 11/12/2024 | Falso installer desktop "SoraAI" | Kit Electron MaaS + loader JS + esecuzione EXE in memoria via Rust (`memexec`) | Payload finale non recuperato |
| B | 16/01/2025 | Falso video `video_for_you.mp4 - openai.com` (`.com` camuffato) | Infostealer Python Braodo-like, payload scaricato da GitHub a ogni avvio | **Furto confermato**: 19 password, 504 cookie, 1 carta di credito → Telegram |

La persistenza della campagna B è sopravvissuta **21 mesi** (fino al 03/10/2026) senza essere rilevata dagli antivirus.

## Perché questo caso è interessante

1. **Il kit Electron è stato recuperato con l'intero ambiente di sviluppo**: `.env` con ID affiliato (modello pay-per-install), server payload e Redis di tracciamento, `Cargo.toml`, istruzioni per sviluppatori, percorso della macchina di build (`M:\electron\...`) e icone per ~15 brand da impersonare (Sora, MidJourney, Leonardo AI, Runway, Meta, Chrome...).
2. **Dead drop su Google Calendar** per la risoluzione dell'URL del payload.
3. **Offuscamento batch a 5 livelli** mai documentato in questa combinazione: falso BOM UTF-16, variabili spazzatura, labirinto di goto, dead code aritmetico, assemblaggio runtime del comando tramite substring di variabili d'ambiente → il payload non esiste in chiaro nel file.
4. **Osservazione dal lato vittima** di un'esfiltrazione Braodo-like grazie al log di debug lasciato dal malware stesso.

## Struttura del repository

```
iocs/iocs.csv                     Indicatori di compromissione (defangati)
yara/                             Regole YARA per il rilevamento
analysis/9a_bat_deobfuscation.md  Analisi dello script di persistenza offuscato
analysis/soraai_electron_kit.md   Analisi del kit Electron MaaS
analysis/mitre_attack_mapping.md  Mappatura MITRE ATT&CK
```

**Nessun campione** è incluso in questo repository. Il campione `9a.bat` è condiviso con la comunità di ricerca tramite **MalwareBazaar (abuse.ch)**, SHA256 `197F763BCD619F96E8C8C9074C9F483CCDB31E49B6E51C115D086A48BED17DE0` (zip protetto da password, convenzione `infected`). Le altre evidenze originali sono disponibili per ricercatori accreditati tramite i contatti nel paper Zenodo.

## IoC principali (defangati)

| Tipo | Valore |
|---|---|
| Dominio | `openai-index-sora-video[.]com` |
| Dominio | `appliedaibusiness[.]com` |
| Dominio | `aisoraplus[.]com` |
| Dominio | `app-tools[.]info` |
| IPv4 | `82.197.67[.]174` (payload server, Contabo) |
| IPv4:porta | `45.93.20[.]174:6379` (Redis tracking) |
| URL dead drop | `calendar.app.google/Cib52LrMMujMewsE9` |
| URL payload | `raw.githubusercontent[.]com/hacker9xclone/111/refs/heads/master/mrxw` |
| Telegram | bot `7692901771`, chat `-1002407933384` |
| Persistenza | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSecurity` → `%PUBLIC%\Downloads\xmetavip2\9a.bat` |
| SHA256 | `197F763BCD619F96E8C8C9074C9F483CCDB31E49B6E51C115D086A48BED17DE0` (9a.bat) |
| SHA256 | `9777AC1267C9EE6EBC57468DD25F1714F9120583A875164DD015C030D5DEBBF6` (SoraAI.exe) |

Elenco completo in [`iocs/iocs.csv`](iocs/iocs.csv).

## Licenza

Documentazione e regole: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). La citazione è gradita.
