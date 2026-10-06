rule SoraAI_FakeInstaller_Electron_Kit
{
    meta:
        description = "Rileva artefatti del kit MaaS di falsi installer AI (campagna SoraAI, dicembre 2024)"
        author = "Fabio Ghioni"
        reference = "https://doi.org/10.5281/zenodo.23170944"
        date = "2026-10-05"
        campaign = "A - SoraAI fake installer"
        hash = "5BD2DDD90BB5451BA1CA6662E8F45B2A89DE5F9287CC4F4B5E8E9A68B00A90C6" // app.asar
    strings:
        $env1 = "PARTENER_ID" ascii
        $env2 = "GOOGLE_PROXY=https://calendar.app.google" ascii
        $env3 = "app-tools.info" ascii
        $ipc1 = "invoke-start-install" ascii
        $ipc2 = "invoke-offer-get" ascii
        $pkg1 = "\"OpenAiLLC\"" ascii
        $fn1  = "jumpUp" ascii
        $hdr1 = "ivbase64" ascii
        $hdr2 = "secretkey" ascii
    condition:
        3 of them
}

rule SoraAI_Kit_Memexec_Rust_Module
{
    meta:
        description = "Modulo nativo Rust/Neon per esecuzione EXE in memoria (fileless)"
        campaign = "A - SoraAI fake installer"
        date = "2026-10-05"
    strings:
        $s1 = "memexec_exe" ascii
        $s2 = "use neon::prelude" ascii
        $s3 = "crate-type = [\"cdylib\"]" ascii
        $s4 = "cryptify" ascii
    condition:
        2 of them
}

rule SoraAI_Kit_AntiAnalysis_ProcessList
{
    meta:
        description = "Lista anti-analisi del kit (42 tool di reversing/VM)"
        campaign = "A - SoraAI fake installer"
        date = "2026-10-05"
    strings:
        $a = "wireshark" ascii nocase
        $b = "processhacker" ascii nocase
        $c = "x64dbg" ascii nocase
        $d = "joeboxserver" ascii nocase
        $e = "scylla_x64" ascii nocase
        $f = "find-process" ascii
    condition:
        4 of ($a,$b,$c,$d,$e) and $f
}
