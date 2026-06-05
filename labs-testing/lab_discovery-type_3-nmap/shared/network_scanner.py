"""
Questo script esegue una scansione di rete per identificare le subnet, gli host attivi e 
le porte attive utilizzando il comando nmap, al fine di mappare l'infrastruttura per le 
attivita' di analisi del tirocinio. Lo script inoltre legge, se presente nella directory
shared del lab di test, un file .json per il confronto con i risultati di scansione attesi.
"""
__author__ = "Stefano Strambi"
__version__ = "1.1"



import subprocess
import json
import re
import os

TARGET_SUBNETS = ["110.0.0.0/24","110.0.4.0/24","210.0.3.0/24","10.0.1.0/30","10.0.0.0/30","210.0.4.0/24"] #definisco le subnet per il lab type_3
PORT_RANGE = "80-9000"
OUTPUT_JSON = "scan_results.json"
EXPECTED_JSON = "scan_expected.json"

scan_data = {} #dizionario inizialmente vuoto per contenere i dati della network discovery
               #scan_data ha come chiavi le subnet e come valori le mappe di ip degli host attivi;
               #le mappe di ip hanno come chiavi gli indirizzi ip e come valori le mappe di dettaglio per quell'ip;
               #definisco nella mappa di dettagli la corrispondenza chiave "ports" e valore una lista di porte; 



#funzione che trova ed inserisce tutte le subnet e gli host attivi, presenti nella rete, all'interno di scan_data
def network_discovery():
    print("=============================================")
    print("||    NETWORK DISCOVERY: Scan iniziato     ||")
    print("=============================================")

    for subnet in TARGET_SUBNETS:
        scan_data[subnet] = {}

        #comando nmap: -sn prende solo ip senza test porte; --open riporta solo gli host attivi (che hanno risposto); -oG formato "grepable" per info host su unica riga
        #ad ogni ip nmap invia una serie di pacchetti (ARP se in LAN; ICMP, TCP SYN/ACK o altri tipi di ping se fuori da LAN)
        result = subprocess.run(["nmap","-sn","--open","-oG", "-", subnet], capture_output=True, text=True) #capture_output per evitare stampe, text per renderlo formato testuale e non byte
        
        for line in result.stdout.splitlines(): #separo l'output in righe

            if line.startswith("Host:"):

                #regular expression per gli ip: r per prendere testo grezzo, \b per definire la grandezza da estrarre, \d per sole cifre numeriche, ?: per evitare di creare un gruppo con le tonde
                ip_found = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)

                if ip_found:
                    ip = ip_found.group(0) #estrae dal match della regex il valore senza metadati
                    scan_data[subnet][ip] = {"ports": []}
                    print(f"Host trovato: {ip}! Lo aggiungo...")

    print("Fase di network discovery terminata.\n")




#funzione che esegue il port scanning per ogni host attivo trovato precedentemente
def port_scanning(): 
    print("=============================================")
    print("||      PORT SCANNING: Scan iniziato       ||")
    print("=============================================")

    for subnet, ip_map in scan_data.items():

        for ip, details_map in ip_map.items():

            print(f"Controllo porte aperte su: {ip}")

            #-p: per specificare il range di porte; --open: segna solo le porte aperte trovate; -T4: velocita' di scan aumentata, timeout veloci e richieste in parallelo;
            #-oG: output in formato Grepable;   
            result = subprocess.run(["nmap", "-p", PORT_RANGE, "--open", "-T4", "-oG", "-", ip], capture_output=True, text=True)

            open_ports = []
            for line in result.stdout.splitlines():
                if "Ports" in line:
                    ports_found = re.findall(r'(\d+)/open/', line) #uso findall() perché non voglio fermarmi al primo match

                    if ports_found:
                        print(f"Trovate porte aperte su {ip}!")
                        print(f"Aggiungo le porte al file di report...")
                        open_ports = [int(port) for port in ports_found] #trasformo le stringhe della regex in valori numerici"
                        details_map["ports"] = sorted(open_ports)
                    else:
                        print(f"Nessuna porta aperta trovata su {ip}.")
                        details_map["ports"] = []
                    
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
            expected_data = json.load(f)
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
        common_ips = ips_found.intersection(ips_expected)

        for ip in sorted(common_ips):
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

#verifica se e' stato trovato almeno un host in una qualsiasi subnet. any controlla che ci sia almeno un dizionario di ip non vuoto
host_trovati = any(scan_data[subnet] for subnet in scan_data)

if host_trovati:
    port_scanning()
    save_results()
    compare_scans()
else:
    print("Nessun host attivo ha risposto ai comandi di network discovery. Scansione interrotta.\n")

print("Script terminato con successo.")