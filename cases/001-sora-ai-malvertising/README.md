# Case 001 — Sora AI Malvertising Analysis

**Technical analysis of a double "Sora AI" malvertising infection (December 2024 – January 2025): a fake-installer Electron MaaS kit with Rust fileless execution, and a "Braodo-like" Python infostealer with Telegram exfiltration.**

🇮🇹 [Versione italiana](README.it.md)

📄 Full paper (PDF) on Zenodo: [10.5281/zenodo.23170944](https://doi.org/10.5281/zenodo.23170944) (all versions; current v0.2: [10.5281/zenodo.23194008](https://doi.org/10.5281/zenodo.23194008)) — Markdown in this repository: [English](docs/paper_en.md) | [Italiano](docs/paper_it.md)

---

## ⚠️ Disclaimer

This repository is published **exclusively for research and defensive purposes** (cybersecurity, threat intelligence, education). It contains no malware samples, no executables, no runnable offensive code. Indicators of compromise are **defanged** by convention (`hxxp://`, `domain[.]com`). The author is not responsible for misuse of the information published here. If you operate a service mentioned in this research (hosting, platform), abuse contacts are listed in the paper.

## TL;DR

Between December 2024 and January 2025, a Windows workstation was infected twice by fake "Sora AI" software promoted through social media ads:

| # | Date | Bait | Malware | Outcome |
|---|---|---|---|---|
| A | 2024-12-11 | Fake "SoraAI" desktop installer | Electron MaaS kit + JS loader + in-memory EXE execution via Rust (`memexec`) | Final payload not recovered |
| B | 2025-01-16 | Fake video `video_for_you.mp4 - openai.com` (disguised `.com`) | Braodo-like Python infostealer, payload fetched from GitHub at every startup | **Confirmed theft**: 19 passwords, 504 cookies, 1 credit card → Telegram |

Campaign B's persistence survived **21 months** (until 2026-10-03) without being detected by antivirus. A Microsoft Defender re-test on 2026-10-06 (security intelligence 1.459.574.0) still reports no threats in the loader.

## Why this case matters

1. **The Electron kit was recovered with its entire development environment**: `.env` with affiliate ID (pay-per-install model), payload and Redis tracking servers, `Cargo.toml`, developer instructions, build-machine paths (`M:\electron\...`), and icons for ~15 impersonated brands (Sora, MidJourney, Leonardo AI, Runway, Meta, Chrome...).
2. **Google Calendar dead drop** for payload URL resolution.
3. **5-layer batch obfuscation** never documented in this combination: fake UTF-16 BOM, junk variables, goto maze, arithmetic dead code, runtime command assembly via environment-variable substrings → the payload never exists in plaintext in the file.
4. **Victim-side observation** of a Braodo-like exfiltration, thanks to the debug log the malware itself left behind.

## Repository structure

```
iocs/iocs.csv                     Indicators of compromise (defanged)
yara/                             YARA detection rules
analysis/9a_bat_deobfuscation.md  Obfuscated persistence script analysis
analysis/soraai_electron_kit.md   Electron MaaS kit analysis
analysis/mitre_attack_mapping.md  MITRE ATT&CK mapping
docs/paper_en.md                  Full paper (English, AI-friendly Markdown)
docs/paper_it.md                  Paper completo (italiano)
```

**No samples** are included in this repository. The `9a.bat` sample (SHA256 `197F763BCD619F96E8C8C9074C9F483CCDB31E49B6E51C115D086A48BED17DE0`) is shared with the research community via **MalwareBazaar (abuse.ch)** inside the archive entry [`419f513be822e01ebc1494ac1c20d78de701eaeae5fa025625550ee518c41a5f`](https://bazaar.abuse.ch/sample/419f513be822e01ebc1494ac1c20d78de701eaeae5fa025625550ee518c41a5f/) (zip, password `infected`). On 2026-10-06 it was also uploaded as a standalone entry: [`197f763b…`](https://bazaar.abuse.ch/sample/197f763bcd619f96e8c8c9074c9f483ccdb31e49b6e51c115d086a48bed17de0/). Other original evidence is available to accredited researchers via the contacts in the Zenodo paper.

## Main IoCs (defanged)

| Type | Value |
|---|---|
| Domain | `openai-index-sora-video[.]com` |
| Domain | `appliedaibusiness[.]com` |
| Domain | `aisoraplus[.]com` |
| Domain | `app-tools[.]info` |
| IPv4 | `82.197.67[.]174` (payload server, Contabo) |
| IPv4:port | `45.93.20[.]174:6379` (Redis tracking) |
| URL dead drop | `calendar.app.google/Cib52LrMMujMewsE9` |
| URL payload | `raw.githubusercontent[.]com/hacker9xclone/111/refs/heads/master/mrxw` |
| Telegram | bot `7692901771`, chat `-1002407933384` |
| Persistence | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSecurity` → `%PUBLIC%\Downloads\xmetavip2\9a.bat` |
| SHA256 | `197F763BCD619F96E8C8C9074C9F483CCDB31E49B6E51C115D086A48BED17DE0` (9a.bat) |
| SHA256 | `9777AC1267C9EE6EBC57468DD25F1714F9120583A875164DD015C030D5DEBBF6` (SoraAI.exe) |

Full list in [`iocs/iocs.csv`](iocs/iocs.csv).

## License

Documentation and rules: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Attribution appreciated.
