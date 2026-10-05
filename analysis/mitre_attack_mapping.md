# Mappatura MITRE ATT&CK

Campagna A = falso installer Electron "SoraAI" (dicembre 2024)
Campagna B = infostealer Python Braodo-like (gennaio 2025)

| Tattica | ID | Tecnica | Campagna | Evidenza |
|---|---|---|---|---|
| Initial Access | T1189 | Drive-by Compromise | A, B | Annunci sponsorizzati sui social → landing fake |
| Execution | T1059.007 | JavaScript | A | Loader JS offuscato in app.asar |
| Execution | T1059.003 | Windows Command Shell | B | `9a.bat` |
| Execution | T1059.006 | Python | B | `pw.exe -c` |
| Execution | T1204.002 | Malicious File | A, B | Click su falso installer / falso video |
| Execution | T1218.005 | Mshta | B | Rilancio nascosto via `mshta vbscript:` |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder | B | `HKCU\...\Run\WindowsSecurity` |
| Defense Evasion | T1620 | Reflective Code Loading | A | `memexec` Rust: EXE in memoria |
| Defense Evasion | T1036.007 | Double File Extension | B | `video_for_you.mp4 - openai.com` |
| Defense Evasion | T1036.004 | Masquerade Task or Service | B | Voce Run "WindowsSecurity" |
| Defense Evasion | T1027 | Obfuscated Files or Information | A, B | Loader base64; batch a 5 livelli |
| Defense Evasion | T1027.013 | Encrypted/Encoded File | A | Script cifrato con `ivbase64`/`secretkey` |
| Defense Evasion | T1497.001 | System Checks | A | `checkProcess.js` (42 tool di analisi) |
| Defense Evasion | T1218 | System Binary Proxy Execution | B | `pw.exe` = `pythonw.exe` firmato PSF rinominato |
| Credential Access | T1555.003 | Credentials from Web Browsers | B | 19 password esfiltrate |
| Credential Access | T1539 | Steal Web Session Cookie | B | 504 cookie via debug port `localhost:9222` |
| Discovery | T1614 | System Location Discovery | B | Geolocalizzazione via `ip-api.com` |
| Collection | T1005 | Data from Local System | B | Zip `[IT_...] [nome macchina].zip` |
| C2 | T1102 | Web Service | A, B | Google Calendar (dead drop), GitHub (hosting payload), Dropbox (dropper) |
| C2 | T1071.001 | Web Protocols | B | HTTPS → Telegram Bot API |
| Exfiltration | T1567.002 | Exfiltration to Cloud Storage | B | `sendDocument` verso chat Telegram `-1002407933384` |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | B | Archivio inviato sul canale bot |
