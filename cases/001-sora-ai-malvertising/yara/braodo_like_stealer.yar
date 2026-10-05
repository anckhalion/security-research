rule BraodoLike_9aBAT_Obfuscated_Loader
{
    meta:
        description = "Loader batch offuscato a 5 livelli (persistenza Run\\WindowsSecurity, campagna B gennaio 2025)"
        author = "Fabio Ghioni"
        reference = "https://doi.org/10.5281/zenodo.23170945"
        date = "2026-10-05"
        campaign = "B - Braodo-like Python stealer"
        hash = "197F763BCD619F96E8C8C9074C9F483CCDB31E49B6E51C115D086A48BED17DE0"
    strings:
        // Falso BOM UTF-16 seguito da contenuto ANSI con variabili spazzatura
        $bom = { FF FE 25 }
        // Rilancio nascosto via mshta
        $mshta = "vbscript:createobject(\"wscript.shell\").run" ascii nocase
        // Assemblaggio runtime da substring di variabili d'ambiente
        $sub1 = "DRIVERDATA:~-34," ascii nocase
        $sub2 = "PROGRAMFILES(X86):~-17," ascii nocase
        $sub3 = "LOCALAPPDATA:~-12," ascii nocase
        // Charset personalizzato osservato nel campione
        $charset = "KDOT=PS7sU4zhlIiMLyRCncv3tKbZXEfx5pjrOVmA1BgH9GNk2J0Y8FWd6QqDuoTaew" ascii
    condition:
        ($bom and $mshta) or ($mshta and 2 of ($sub*)) or $charset
}

rule BraodoLike_Stealer_Log_Artefacts
{
    meta:
        description = "Stringhe del log di debug dello stealer (esfiltrazione Telegram, targeting Facebook Ads)"
        campaign = "B - Braodo-like Python stealer"
        date = "2026-10-05"
        note = "Utile per threat hunting su log/EDR, non per file detection"
    strings:
        $tg1 = "api.telegram.org" ascii
        $tg2 = "sendDocument" ascii
        $tg3 = "protect_content=True" ascii
        $fb1 = "graph.facebook.com:443 \"GET /v17.0/me/adaccounts" ascii
        $fb2 = "me/facebook_pages?fields=name%2Clink%2Cfan_count" ascii
        $dbg = "localhost:9222 \"GET /json" ascii
        $loot1 = "All_Passwords.txt" ascii
        $loot2 = "Browser Data: CK:" ascii
    condition:
        ($tg1 and $tg2 and $tg3) or ($fb1 and $fb2) or ($dbg and $loot1) or ($loot1 and $loot2)
}
