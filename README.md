# Network-Analysis-Internship-Project


- **Autore**: Stefano Strambi
- **Titolo**: Progetto di tesi sull'analisi di rete e delle vulnerabilità
- **Data**: Maggio-Luglio 2026



## Descrizione

Questo progetto contiene uno script Python (`network_scanner.py`) per l'analisi automatizzata di reti emulate tramite [Kathara](https://www.kathara.org/), pensato per attività di discovery di rete, scansione porte/servizi e ricerca delle vulnerabilità (CVE) associate ai servizi rilevati, tramite interrogazione del database ufficiale NIST NVD.


## Requisiti

Prima di procedere è necessario disporre di:

- **Docker** — necessario sia per la costruzione delle immagini dei dispositivi di rete usate da Kathara, sia per la loro esecuzione e l'avvio dei relativi container durante il lab.
  Guida ufficiale all'installazione: https://docs.docker.com/get-docker/

- **Kathara** — il network emulator usato per l'avvio dei laboratori di rete.
  - Sito ufficiale: https://www.kathara.org/
  - Guida all'installazione: https://www.kathara.org/docs/install.html
  - Documentazione/comandi: https://github.com/KatharaFramework/Kathara/wiki

Docker deve essere installato e attivo prima di procedere con i passaggi successivi.


## Configurazione dello script

In cima al file `network_scanner.py` sono presenti alcune costanti pensate per essere adattate facilmente in base al contesto d'uso:

- **`TARGET_SUBNETS`** — elenco delle subnet (in notazione CIDR) su cui eseguire la discovery di rete. Il valore presente nel repository è preconfigurato per il laboratorio `lab_discovery-type_3-nmap`; se si utilizza un lab diverso, oppure si modifica la topologia di rete del lab esistente, è necessario aggiornare questo elenco di conseguenza.
- **`TIMEZONE`** — fuso orario (formato IANA, es. `"Europe/Rome"`, `"UTC"`) usato dalla classe ZoneInfo per generare il timestamp nel nome del file dei risultati. Può essere modificato se il lab viene eseguito da una postazione con fuso orario diverso. Il valore non può essere lasciato vuoto: una stringa vuota o non valida genera un errore (`ValueError`) durante il salvataggio dei risultati.


## Setup e avvio del lab

Il test di riferimento è stato effettuato sul laboratorio [`lab_discovery-type_3-nmap`](https://github.com/step-lit/Network-Analysis-Internship-Project/tree/main/labs-testing/lab_discovery-type_3-nmap), che contiene già la versione aggiornata dello script con le subnet del lab specificate, posizionato all'interno della cartella `shared` (la cartella condivisa tra tutti gli host del lab).


### 1. Build delle immagini Docker

Prima di avviare il lab è necessario costruire le immagini Docker richieste:

```bash
bash build-images.sh
```

### 2. (Opzionale) Configurazione della API Key del NIST

Lo script interroga il database NVD del NIST per recuperare le CVE associate ai servizi rilevati. Senza una API key le richieste sono soggette a rate limit più stringenti; con una API key le interrogazioni sono più rapide e affidabili.

Per la configurazione, è necessario creare un file `.env` nella cartella `shared` (la stessa dove si trova lo script) con questo contenuto:

```
NIST_API_KEY=your-key
```

Lo script caricherà automaticamente la chiave all'avvio, se presente.
Per la richiesta di una API key personale o per la propria organizzazione: https://nvd.nist.gov/developers/request-an-api-key


### 3. Avvio del lab con Kathara

Aprire il terminale nella directory principale del lab (quella contenente il file di configurazione del lab, es. `lab.conf`) ed eseguire:

```bash
kathara lstart
```

Kathara avvierà tutti i dispositivi del lab. A questo punto è necessario posizionarsi su una delle macchine che dispone della libreria `nmap3` (nello specifico `pc1`, `pc7` o `pc10`) e lanciare manualmente lo script:


```bash
cd shared
python3 network_scanner.py
```

Lo script verrà così eseguito sull'host scelto e produrrà i risultati della scansione.


### 4. Reperimento dei risultati
- I risultati completi della scansione vengono salvati in formato JSON all'interno della cartella `shared/results/` (creata automaticamente al primo avvio), con nome file riportante data e ora del fuso orario `Europe/Rome` al momento dell'esecuzione (es. `scan_results_19062026_143000.json`). Il fuso orario è impostato esplicitamente nello script per riflettere l'orario locale dell'utente che avvia il lab, indipendentemente dal fuso orario predefinito del container in cui viene eseguito lo script.
- Se nella cartella `shared` è presente un file `scan_expected.json`, lo script confronta automaticamente i risultati ottenuti con quelli attesi, segnalando eventuali differenze (subnet, host o porte nuove/mancanti) direttamente a terminale. Il file dovrà avere la stessa struttura a dizionario del file di risultati (`subnet → host → "ports"`) poiché il confronto avviene esclusivamente a livello di subnet, host e porte: eventuali altre chiavi presenti (es. `"mac"`, `"os"`, `"services"`) per gli host vengono ignorate. Si tratta di una funzionalità pensata ai fini di test.


### 5. Terminazione o riavvio del lab

Una volta concluse le verifiche, per l'arresto e la pulizia di tutti i dispositivi del lab:

```bash
kathara lclean
```

Per un riavvio del lab e di tutti i dispositivi ad esso connessi:

```bash
kathara lrestart
```


## Risorse utili

- Kathara — sito ufficiale: https://www.kathara.org/
- Kathara — documentazione/wiki: https://github.com/KatharaFramework/Kathara/wiki
- Docker — guida installazione: https://docs.docker.com/get-docker/
- NIST NVD — richiesta API key: https://nvd.nist.gov/developers/request-an-api-key
- NIST NVD — documentazione API: https://nvd.nist.gov/developers/vulnerabilities
