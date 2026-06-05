"""
Questo script esegue una scansione di rete per identificare le subnet, gli host, le porte
ed i servizi attivi utilizzando il comando nmap, al fine di mappare l'infrastruttura per le 
attivita' di analisi del tirocinio. Lo script inoltre legge, se presente nella directory
shared del lab di test, un file .json per il confronto con i risultati di scansione attesi.
"""
__author__ = "Stefano Strambi"
__version__ = "1.2"



import subprocess
import json
import re
import os

TARGET_SUBNETS = []
PORT_RANGE = "80-9000"
OUTPUT_JSON = "scan_results.json"
EXPECTED_JSON = "scan_expected.json"

scan_data = {} #dizionario inizialmente vuoto per contenere i dati della network discovery
               #scan_data avra' come chiavi le subnet e come valori le mappe di ip degli host attivi;
               #le mappe di ip hanno come chiavi gli indirizzi ip e come valori le mappe di dettaglio per quell'ip;
               #definisco nella mappa di dettagli la corrispondenza chiave "ports" e valore una lista di porte; 



#funzione che trova ed inserisce tutte le subnet e gli host attivi, presenti nella rete, all'interno di scan_data
def network_discovery():
    print("=============================================")
    print("||    NETWORK DISCOVERY: Scan iniziato     ||")
    print("=============================================")

    for subnet in TARGET_SUBNETS:
        scan_data[subnet] = {}

        #-sn: prende solo l'ip senza fare test porte; --open riporta solo gli host attivi (che hanno risposto); -oG formato "Grepable" per avere le info host su un'unica riga
        #ad ogni ip nmap invia una serie di pacchetti (ARP se in LAN; ICMP, TCP SYN/ACK o altri tipi di ping se fuori da LAN)
        #capture_output non fa stampare a schermo e memorizza in result.stdout e .stderr;
        #uso text per generare output in testo e non byte
        result = subprocess.run(["nmap","-sn","--open","-oG", "-", subnet], capture_output=True, text=True) 
        
        for line in result.stdout.splitlines(): #separo l'output in righe

            if line.startswith("Host:"):

                #r per prendere testo grezzo; \b per definire la grandezza da estrarre;
                #\d per sole cifre numeriche; ?: per evitare di creare un gruppo con le tonde
                ip_found = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line) #re.search ritorna un match object (non subito la stringa)

                if ip_found:
                    ip = ip_found.group(0) #estrae dal match object della regex il valore senza metadati
                    scan_data[subnet][ip] = {"ports": [], "services": {}}
                    print(f"Host trovato: {ip}! Lo aggiungo...")

    print("Fase di network discovery terminata.\n")




#funzione che esegue il port scanning per ogni host attivo trovato precedentemente
#oltre alle porte recupera nome e versione del servizio associato ad ogni porta attiva trovata
def port_scanning(): 
    print("=============================================")
    print("||      PORT SCANNING: Scan iniziato       ||")
    print("=============================================")

    for ip_map in scan_data.values():

        for ip, details_map in ip_map.items():

            print(f"Controllo porte aperte su: {ip}")

            #-p: per specificare il range di porte; --open: segna solo le porte aperte trovate; -T4: velocita' di scan aumentata, timeout veloci e richieste in parallelo;
            #-oG: output in formato Grepable; -sV: identifica servizi e versioni  
            result = subprocess.run(["nmap", "-p", PORT_RANGE, "-sV", "--open", "-T4", "-oG", "-", ip], capture_output=True, text=True)

            open_ports = []
            services_map = {}

            for line in result.stdout.splitlines():
                if "Ports" in line:

                    #vecchia regex che cattura solo le porte senza info per i servizi
                    #ports_found = re.findall(r'(\d+)/open/', line) #uso findall() per non fermarmi al primo match

                    #regex per catturare righe come "(porta)/open/tcp//(servizio)//(versione)/"
                    #[^/]* : cattura tutti i caratteri escludendo le /; se incontra una slash si interrompe
                    #group 0: porta; group 1: servizio; group 2: versione
                    matches_found = re.findall(r'(\d+)/open/tcp//([^/]*)/[^/]*/([^/]*)/', line) #ritorna una lista di tuple, ogni tupla contiene le 3 stringhe utili

                    if matches_found:
                        print(f"Trovate porte aperte su {ip}!")
                        print(f"Aggiungo le porte al file di report...")

                        for match in matches_found: #ogni match corrisponde ad una tupla di stringhe
                            port_string = match[0]
                            service_name = match[1]
                            service_version = match[2]

                            port_int = int(port_string)
                            open_ports.append(port_int)
                            print(f"Aggiunta la porta {port_int}!")

                            if service_version:
                                service = f"{service_name} ({service_version})"
                            else:
                                service = service_name

                            services_map[port_string] = service

                        #faccio gli inserimenti nella mappa relativa all'host attivo
                        details_map["ports"] = sorted(open_ports) 
                        details_map["services"] = services_map
                    else:
                        print(f"Nessuna porta aperta trovata su {ip}.")
                        details_map["ports"] = []
                        details_map["services"] = {}
                    
    print("Fine del port scanning...\n")



#funzione per fare il confronto tra uno scan atteso (scan_expected.json) e lo scan ottenuto con lo script (scan_results.json)
#ritorna un elenco ordinato delle differenze
def compare_scans():
    print("=============================================")
    print("||   SCAN COMPARISON: Confronto iniziato   ||")
    print("=============================================")
    
    # verifico se il file scan_expected.json esiste
    if not os.path.exists(EXPECTED_JSON):
        print(f"Warning: Il file '{EXPECTED_JSON}' non esiste nella directory corrente. Impossibile fare il confronto con lo scan atteso.\n")
        return

    with open(EXPECTED_JSON, "r") as f:
        try:
            expected_data = json.load(f) #struttura dati recuperata dal file di risultati attesi
        except json.JSONDecodeError:
            print(f"Errore: file '{EXPECTED_JSON}' non valido.\n")
            return

    differences_found = False #variabile booleana per catturare il rilevamento di differenze

    subnets_found = set(scan_data.keys())
    subnets_expected = set(expected_data.keys())

    #considero l'unione di tutte le subnet
    all_subnets = subnets_found.union(subnets_expected)

    for sub in sorted(all_subnets):
        
        if sub in subnets_found and sub not in subnets_expected:
            print(f"Nuova subnet (inattesa): {sub}")
            differences_found = True
        elif sub in subnets_expected and sub not in subnets_found:
            print(f"Subnet mancante: {sub}")
            differences_found = True

        #recupero da entrambe le strutture dati i dizionari di ip attivi
        #se il get non trova nulla ritorniamo un dizionario vuoto per i set
        map_ips_found = scan_data.get(sub, {}) 
        map_ips_expected = expected_data.get(sub, {})
        
        #creo degli insiemi di ip per gestire le sottrazioni
        ips_found = set(map_ips_found.keys())
        ips_expected = set(map_ips_expected.keys())

        #eseguo le sottrazioni sugli insiemi di ip
        new_ips = ips_found - ips_expected
        missing_ips = ips_expected - ips_found

        for ip in sorted(new_ips):
            print(f"Nuovo host attivo (inatteso): {ip}")
            differences_found = True
        for ip in sorted(missing_ips):
            print(f"Host mancante: {ip}")
            differences_found = True

        #confronto gli ip (solo quelli comuni ad entrambe le subnet per evitare stampe ovvie)
        #se trovo un nuovo ip inatteso o un ip mancante diventa inutile confrontarlo con valori vuoti di porte e servizi
        common_ips = ips_found.intersection(ips_expected)

        for ip in sorted(common_ips):
            #uso di nuovo le mappe di ip recuperate nel passo prima
            map_details_found = map_ips_found[ip]
            map_details_expected = map_ips_expected[ip]

            #se non trova liste in corrispondenza di ports ritorna una lista vuota
            ports_found = set(map_details_found.get("ports", []))
            ports_expected = set(map_details_expected.get("ports", []))

            new_ports = ports_found - ports_expected
            missing_ports = ports_expected - ports_found

            if new_ports:
                print(f"Nuove porte rilevate per {ip}: {sorted(list(new_ports))}")
                differences_found = True
            if missing_ports:
                print(f"Porte mancanti/chiuse per {ip}: {sorted(list(missing_ports))}")
                differences_found = True

    #se non ho trovato differenze faccio una stampa diversa
    if not differences_found:
        print("Confronto terminato: nessuna differenza rilevata. La rete corrisponde al report atteso.\n")
    else:
        print("Confronto terminato: rilevate differenze rispetto al risultato atteso.\n")



#funzione che salva il report dello scan generando file JSON e YML
def save_results():

    with open(OUTPUT_JSON, "w") as json_file:
        json.dump(scan_data, json_file, indent=4)
    print(f"File JSON {OUTPUT_JSON} creato con successo!\n")



#---------------------
#   main del codice
#---------------------
network_discovery() #esegue la network discovery sui subnet target

#verifica se viene trovato almeno un host in una qualsiasi subnet. any controlla che ci sia almeno un dizionario di ip non vuoto
host_trovati = any(scan_data[subnet] for subnet in scan_data)

if host_trovati:
    port_scanning()
    save_results()
    compare_scans()
else:
    print("Nessun host attivo ha risposto ai comandi di network discovery. Scansione terminata.\n")

print("Script di scansione terminato con successo.")