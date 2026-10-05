# Il kit MaaS "SoraAI" — falso installer Electron con esecuzione fileless (campagna A)

**Installazione:** `%LOCALAPPDATA%\Programs\sora\` ("SoraAI 1.0.6", exe non firmato, Company `OpenAiLLC`, build 09/12/2024)
**SHA256 app.asar:** `5BD2DDD90BB5451BA1CA6662E8F45B2A89DE5F9287CC4F4B5E8E9A68B00A90C6`
**Rilevamento Defender (a posteriori):** `Trojan:JS/GlassWorm.HAF!MTB` sul loader JS.

## Catena di esecuzione

1. Finta finestra "Install" (Electron/Nuxt, 700×300, frameless).
2. Click utente → IPC `invoke-start-install` → `jumpUp()` (`outMutation.js`) → loader JS offuscato base64.
3. Il loader legge un **evento di Google Calendar** (`calendar.app.google/Cib52LrMMujMewsE9`) usato come *dead drop* per ottenere l'URL del payload: l'infrastruttura Google, fidata e raramente bloccata, rende l'URL sostituibile in qualunque momento senza ridistribuire le build.
4. Download di uno script cifrato (header `ivbase64` / `secretkey`).
5. Modulo nativo **Rust/Neon** con crate `memexec` → `memexec_exe(&data)`: **l'EXE finale gira in memoria e non tocca mai il disco**.
6. `checkProcess.js`: uscita immediata se è in esecuzione uno dei 42 tool di analisi (wireshark, procmon, x64dbg, idaq64, joeboxserver, qemu-ga, vboxservice, …).

## L'ambiente di sviluppo lasciato nel pacchetto

L'`app.asar` include file che avrebbero dovuto restare sulla macchina dell'autore:

| File | Contenuto di rilievo |
|---|---|
| `.env` | `HOST` (payload server), `REDIS` (tracking), `PARTENER_ID=6PHM9GG3zOACOOY`, `OFFER=sora`, `GOOGLE_PROXY` (dead drop) |
| `link.txt` | Link payload in chiaro + versione base64 tagged con l'ID affiliato |
| `Cargo.toml` | Dipendenze `memexec 0.2`, `cryptify 3.1.1` (offuscamento stringhe), `neon`; commento "use 3 instead of 1 to improve cryptablity" |
| `readme.txt` | Istruzioni interne: "for work need rust", percorso `M:\electron\electron\load.js` |
| icone | Asset per ~15 brand: Sora, Haiper, Leonardo AI, MidJourney, Ideogram, Runway, PicsArt, Akool, Uizard, Slidesgo, Postman, Chrome, Opera, Mozilla, Meta |

## Il modello economico: pay-per-install

- `PARTENER_ID` è l'identificativo di un **affiliato**: chi distribuisce le build riceve una provvigione per installazione.
- La pagina post-installazione `hxxps://replicate-6phm9gg3zoacooy.app-tools[.]info/explore` incorpora l'ID (minuscolo) nel sottodominio → tracciamento per-affiliato lato server.
- Il server Redis (`45.93.20[.]174:6379`) è plausibilmente il contatore degli eventi (installazioni, click) usato per i pagamenti.
- Il set di icone multi-brand indica che la stessa infrastruttura genera campagne per esche diverse: `OFFER=sora` è solo la configurazione corrente.

## Infrastruttura

| Risorsa | Valore | Provider |
|---|---|---|
| Payload server | `82.197.67[.]174` | Contabo GmbH (DE) — abuse@contabo.de |
| Tracking Redis | `45.93.20[.]174:6379` | UFO Technologies Ltd (GB) — abuse@changway.hk |
| Dead drop | Google Calendar short link | Google |
| Landing | `openai-index-sora-video[.]com`, `appliedaibusiness[.]com` | — |
| Post-install | `app-tools[.]info` | — |

## Indizi di attribuzione (deboli)

- Commento in russo in `helper.js`, copiato dalla documentazione MDN russa.
- Modello ad affiliazione tipico dell'ecosistema PPI russofono.
- Nessun artefatto che consenta attribuzione forte. **Il payload finale non è stato recuperato**: non è determinabile se e cosa sia stato eseguito in memoria l'11/12/2024.
