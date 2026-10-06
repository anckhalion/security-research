# Security Research

**Independent cybersecurity research: case studies, IoCs, YARA rules, and forensic methodology. Real incidents, documented end-to-end — from infection to publication.**

🇮🇹 [Versione italiana](README.it.md)

---

## About

This repository collects my security research cases: real-world malware incidents analyzed forensically and published with full technical documentation, indicators of compromise, detection rules, and MITRE ATT&CK mapping. Each case lives in `cases/` and is accompanied by a peer-reviewable paper deposited on Zenodo (DOI) and a long-form article.

**Ethics policy:** no live malware samples, no victim-identifying data, all IoCs defanged. Samples, when shareable, are distributed through [MalwareBazaar](https://bazaar.abuse.ch/) under their research conventions.

## Cases

| # | Date | Title | Paper | Contents |
|---|---|---|---|---|
| [001](cases/001-sora-ai-malvertising/) | Oct 2026 | **Two Waves, One Brand** — double "Sora AI" malvertising infection: Electron MaaS fake-installer kit + Braodo-like Python infostealer | [doi:10.5281/zenodo.23170944](https://doi.org/10.5281/zenodo.23170944) | IoCs, YARA, MITRE mapping, deobfuscation analysis |

### Case 001 — highlights

- A fake "SoraAI" Electron installer recovered **with the author's entire development environment**: `.env` with pay-per-install affiliate ID, tracking infrastructure, build paths, icons for ~15 impersonated brands
- **Google Calendar dead drop** for payload URL resolution; **Rust `memexec`** module for in-memory (fileless) EXE execution
- A 5-layer obfuscated batch loader (`9a.bat`): fake UTF-16 BOM, junk env vars, goto maze, arithmetic dead code, runtime command assembly — the payload never exists in plaintext
- Confirmed theft (19 passwords, 504 cookies, 1 credit card) documented by **the malware's own debug log**; exfiltration via Telegram Bot API
- Persistence survived **21 months** undetected by signature-based AV; on 2026-10-06 the loader still passes Microsoft Defender's signatures
- Sample on MalwareBazaar: `9a.bat` (SHA256 `197F763BCD619F96E8C8C9074C9F483CCDB31E49B6E51C115D086A48BED17DE0`) inside the archive entry [`419f513b…`](https://bazaar.abuse.ch/sample/419f513be822e01ebc1494ac1c20d78de701eaeae5fa025625550ee518c41a5f/) (zip, password `infected`) and as a standalone entry [`197f763b…`](https://bazaar.abuse.ch/sample/197f763bcd619f96e8c8c9074c9f483ccdb31e49b6e51c115d086a48bed17de0/)

## Repository structure

```
cases/
  001-sora-ai-malvertising/
    README.md / README.it.md     Case overview (EN / IT)
    analysis/                    Technical deep-dives
    iocs/                        Indicators of compromise (defanged)
    yara/                        Detection rules
    docs/                        Full paper (EN/IT, AI-friendly Markdown)
```

## License

[CC BY 4.0](LICENSE). Attribution appreciated.
