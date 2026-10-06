# Security Research

**Ricerca indipendente di sicurezza informatica: casi di studio, IoC, regole YARA e metodologia forense. Incidenti reali, documentati dall'infezione alla pubblicazione.**

🇬🇧 [English version](README.md)

---

## Il progetto

Questo repository raccoglie i miei casi di ricerca in ambito sicurezza: incidenti malware reali, analizzati forensemente e pubblicati con documentazione tecnica completa, indicatori di compromissione, regole di rilevamento e mappatura MITRE ATT&CK. Ogni caso vive in `cases/` ed è accompagnato da un paper depositato su Zenodo (con DOI) e da un articolo divulgativo.

**Politica etica:** nessun campione di malware live, nessun dato che identifichi le vittime, tutti gli IoC defangati. I campioni, quando condivisibili, sono distribuiti tramite [MalwareBazaar](https://bazaar.abuse.ch/) secondo le convenzioni della comunità di ricerca.

## Casi pubblicati

| # | Data | Titolo | Paper | Contenuti |
|---|---|---|---|---|
| [001](cases/001-sora-ai-malvertising/) | Ott 2026 | **Due ondate, un solo brand** — doppia infezione da malvertising "Sora AI": kit MaaS di falsi installer Electron + infostealer Python Braodo-like | [doi:10.5281/zenodo.23170944](https://doi.org/10.5281/zenodo.23170944) | IoC, YARA, mappatura MITRE, analisi deoffuscazione |

### Caso 001 — punti salienti

- Falso installer Electron "SoraAI" recuperato **con l'intero ambiente di sviluppo dell'autore**: `.env` con ID affiliato pay-per-install, infrastruttura di tracciamento, percorsi di build, icone per ~15 brand imitabili
- **Dead drop su Google Calendar** per la risoluzione dell'URL del payload; modulo **Rust `memexec`** per esecuzione fileless in memoria
- Loader batch a 5 livelli di offuscamento (`9a.bat`): falso BOM UTF-16, variabili spazzatura, labirinto di goto, dead code aritmetico, assemblaggio runtime del comando — il payload non esiste mai in chiaro
- Furto confermato (19 password, 504 cookie, 1 carta di credito) documentato dal **log di debug lasciato dal malware stesso**; esfiltrazione via Telegram Bot API
- Persistenza sopravvissuta **21 mesi** senza rilevamento da parte degli AV a firma; al 06/10/2026 il loader supera ancora le firme di Microsoft Defender
- Campione su MalwareBazaar: `9a.bat` (SHA256 `197F763BCD619F96E8C8C9074C9F483CCDB31E49B6E51C115D086A48BED17DE0`) dentro l'archivio [`419f513b…`](https://bazaar.abuse.ch/sample/419f513be822e01ebc1494ac1c20d78de701eaeae5fa025625550ee518c41a5f/) (zip, password `infected`) e come voce autonoma [`197f763b…`](https://bazaar.abuse.ch/sample/197f763bcd619f96e8c8c9074c9f483ccdb31e49b6e51c115d086a48bed17de0/)

## Struttura del repository

```
cases/
  001-sora-ai-malvertising/
    README.md / README.it.md     Panoramica del caso (EN / IT)
    analysis/                    Approfondimenti tecnici
    iocs/                        Indicatori di compromissione (defangati)
    yara/                        Regole di rilevamento
    docs/                        Paper completo (EN/IT, Markdown AI-friendly)
```

## Licenza

[CC BY 4.0](LICENSE). La citazione è gradita.
