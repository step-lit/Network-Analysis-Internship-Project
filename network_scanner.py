"""
Questo script esegue una scansione di rete per identificare le subnet, gli host, le porte ed i servizi 
attivi utilizzando la libreria python3-nmap (nmap3), al fine di mappare l'infrastruttura per le 
attivita' di analisi del tirocinio. Lo script inoltre legge, se presente nella directory
shared del lab di test, un file .json per il confronto con i risultati di scansione attesi.
"""
__author__ = "Stefano Strambi"
__version__ = "1.3-wip"



import json
import os
import nmap3
from datetime import datetime
from zoneinfo import ZoneInfo

TARGET_SUBNETS = ["110.0.0.0/24","110.0.4.0/24","210.0.3.0/24","10.0.1.0/30","10.0.0.0/30","210.0.4.0/24"]

EXPECTED_JSON = "scan_expected.json"

scan_data = {} #dizionario inizialmente vuoto per contenere i dati della network discovery
               #scan_data avra' come chiavi le subnet e come valori le mappe di ip degli host attivi;
               #le mappe di ip hanno come chiavi gli indirizzi ip e come valori le mappe di dettaglio per quell'ip;
               #definisco nella mappa di dettagli relativa all'host informazioni come nome, porte, servizi attivi, os ed altro; 


#------------------------------------------------------------------------------------------------------------------#
# FUNZIONI PER L'HOST DISCOVERY
#------------------------------------------------------------------------------------------------------------------#


#funzione che trova ed inserisce tutte le subnet e gli host attivi, presenti nella rete, all'interno di scan_data
def network_discovery():
    print("=============================================================")
    print("||              HOST DISCOVERY: Scan iniziato              ||")
    print("=============================================================")

    nmap = nmap3.NmapScanTechniques() #oggetto della libreria nmap3 per scansioni ad alto livello

    for subnet in TARGET_SUBNETS:
        scan_data[subnet] = {}

        #nmap_ping_scan esegue il comando "nmap -v -oX -sP subnet";
        #viene usato il parametro retrocompatibile -sP, 
        #ufficialmente sostituito da -sn (no port scan) nelle versioni piu' recenti di nmap;
        result = nmap.nmap_ping_scan(subnet)
        
        for key, value in result.items(): #key: host ip; value: dict of details     

            #recupero dallo scan solo gli host attivi che hanno "state" = "up"
            if isinstance(value, dict) and value.get("state", {}).get("state") == "up":
                ip = key
                print(f"Host trovato: {ip}! Lo aggiungo...")

                #estraggo lo stato ed il mac address dell'ip
                state_info = value.get("state", {})
                reason = state_info.get("reason", "")
                mac_info = value.get("macaddress")

                mac_address = "null"

                #se la risposta risulta da se stesso segna localhost
                if reason == "localhost-response":
                    mac_address = "localhost"
                #altrimenti viene aggiunto il suo valore
                elif mac_info:
                    mac_address = mac_info.get("addr", "null")

                #inizializzo la struttura dati per l'ip trovato
                scan_data[subnet][ip] = {
                    "mac": mac_address,
                    "os": "unknown",
                    "ports": [],
                    "services": {}
                }

    print("Fase di host discovery terminata.\n")


#------------------------------------------------------------------------------------------------------------------#
# FUNZIONI PER IL PORT SCANNING
#------------------------------------------------------------------------------------------------------------------#

#funzione che processa lo scan delle porte, inclusi i servizi attivi, per un singolo host
#aggiorna direttamente details_map con le chiavi "ports" e "services"
def process_ports(host_data, details_map):
    ports_list = host_data.get("ports", [])

    if not isinstance(ports_list, list) or len(ports_list) == 0:
        details_map["ports"] = []
        details_map["services"] = {}
        return

    open_ports = []
    services_map = {}

    for port_info in ports_list:
        port_str = port_info.get("portid")
        protocol = port_info.get("protocol", "tcp")

        #scarto le porte open|filtered perche' potrebbero essere uno stato di UDP senza risposta
        state = port_info.get("state", "")
        if state == "open|filtered":
            continue
                    
        #se non trova una stringa sulla chiave portid salta la porta
        if not port_str:
            continue
                    
        port_int = int(port_str)
        open_ports.append(port_int)
        print(f"   -> adding port: {port_int}/{protocol}")

        #estraggo il servizio
        service_info = port_info.get("service", {})
        service_name = service_info.get("name", "")
        service_product = service_info.get("product", "")
        service_version = service_info.get("version", "")
        service_extrainfo = service_info.get("extrainfo", "")

        details = []
        if service_product:
            details.append(service_product)
        if service_version:
            details.append(f"({service_version})")
        if service_extrainfo:
            details.append(service_extrainfo)

        if details:
            service_desc = f"{service_name}: {' '.join(details)}"
        else:
            service_desc = service_name

        #nella stringa per il servizio inserisco sia la porta che il protocollo
        services_map[f"{port_str}/{protocol}"] = service_desc

    #con set() rimuovo duplicati numerici: nella lista di porte la conto solo una volta
    #nel caso in cui una porta sia stata trovata sia per protocollo tcp che udp
    details_map["ports"] = sorted(list(set(open_ports)))
    details_map["services"] = services_map



#funzione che processa l'os fingerprinting per un singolo host
#aggiorna direttamente details_map con la chiave "os"
#riporta tutti i match con accuracy >= best_accuracy - tolerance
def process_os(host_data, details_map):
    os_matches = host_data.get("osmatch", [])

    if not os_matches and isinstance(os_matches, list):
        details_map["os"] = ""
        return

    best_accuracy = int(os_matches[0].get("accuracy", "0"))

    #tolerance per l'accuracy (includo tutti gli os rilevati con accuracy best_accuracy-tolerance)
    tolerance = 2
    min_accepted_accuracy = best_accuracy - tolerance 

    #raccolgo i match nel range di tolleranza
    top_matches = [m for m in os_matches if int(m.get("accuracy", "0")) >= min_accepted_accuracy]

                
    #creo una stringa che riporta gli os e l'accuracy associata ad essi
    os_details_list = []
    for m in top_matches:
        name = m.get("name", "")
        acc = m.get("accuracy", "")
        os_details_list.append(f"{name} ({acc}%)")

    details_map["os"] = " | ".join(os_details_list)
    print(f"   -> OS: {details_map['os']}")



#funzione che esegue il port scanning per ogni host attivo trovato precedentemente
#oltre alle porte recupera nome e versione del servizio associato ad ogni porta attiva trovata
def port_scanning(): 
    print("=============================================================")
    print("||               PORT SCANNING: Scan iniziato              ||")
    print("=============================================================")

    nmap = nmap3.Nmap()
    
    for ip_map in scan_data.values():

        for ip, details_map in ip_map.items():

            print(f"Controllo porte aperte ed OS fingerprinting su {ip}...")

            # -sS: TCP SYN scan; -sU: UDP scan; -sV: Service version; -O: OS Fingerprinting
            #--open: active ports only; --max-retries, --min-rate: just 1 retry and 1000 packets/s to speed up UDP scan
            result = nmap.scan_top_ports(ip, 1000, args="-sS -sU -sV -O --open -T4 --max-retries 1 --min-rate 1000")

            host_data = result.get(ip, {})

            #chiamata alle funzioni che processano porte (inclusi i servizi) ed os per l'ip
            process_ports(host_data, details_map)
            process_os(host_data, details_map)

    print("Fine del port scanning...\n")


#------------------------------------------------------------------------------------------------------------------#
# FUNZIONI PER IL COMPARE SCAN
#------------------------------------------------------------------------------------------------------------------#


#funzione che ritorna un booleano per controllare e stampare differenze tra due set
#parametri: set_a contiene i valori trovati, set_b i valori attesi, msg_new e msg_missing sono le stampe richieste
def check_diffs(set_a, set_b, msg_new, msg_missing):
    new_items = set_a - set_b
    missing_items = set_b - set_a

    #se entrambi i set sono vuoti non ci sono differenze
    if not set_a and not set_b:
        return False
    
    for item in sorted(new_items):
        print(f"{msg_new}: {item}")
    for item in sorted(missing_items):
        print(f"{msg_missing}: {item}")

    return True


#funzione che chiama check_diffs per confrontare le subnets trovate con quelle attese
def compare_subnets(subnets_found, subnets_expected):
    return check_diffs(subnets_found, subnets_expected, "Nuova subnet (inattesa)", "Subnet mancante")


#funzione che chiama check_diffs per confrontare gli ip trovati con quelli attesi 
def compare_hosts(ips_found, ips_expected):
    return check_diffs(ips_found, ips_expected, "Nuovo host attivo (inatteso)", "Host mancante")


#funzione che confronta le porte 
def compare_ports(ip, details_found, details_expected):
    ports_found    = set(details_found.get("ports", []))
    ports_expected = set(details_expected.get("ports", []))
    
    new_ports = ports_found - ports_expected
    missing_ports = ports_expected - ports_found
    
    diffs = False

    if new_ports:
        print(f"Nuove porte rilevate per {ip}: {sorted(new_ports)}")
        diffs = True
    if missing_ports:
        print(f"Porte mancanti/chiuse per {ip}: {sorted(missing_ports)}")
        diffs = True
    return diffs


#funzione per fare il confronto tra uno scan atteso (EXPECTED_JSON) e lo scan ottenuto con lo script (OUTPUT_JSON).
#confronta: subnet presenti, host attivi per subnet, porte aperte per host, chiavi dei servizi (porta/protocollo)
def compare_scans():
    print("=============================================================")
    print("||           SCAN COMPARISON: Confronto iniziato           ||")
    print("=============================================================")
    
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

    subnets_found = set(scan_data.keys())
    subnets_expected = set(expected_data.keys())

    differences_found = compare_subnets(subnets_found, subnets_expected)

    #analizza le subnet comuni (intersezioni dei set)
    for sub in sorted(subnets_found.intersection(subnets_expected)):
        map_ips_found = scan_data.get(sub, {})
        map_ips_expected = expected_data.get(sub, {})

        ips_found = set(map_ips_found.keys())
        ips_expected = set(map_ips_expected.keys())

        if compare_hosts(ips_found, ips_expected):
            differences_found = True

        #analizzo gli host comuni (intersezione dei set)
        for ip in sorted(ips_found.intersection(ips_expected)):
            if compare_ports(ip, map_ips_found[ip], map_ips_expected[ip]):
                differences_found = True

    if not differences_found:
        print("Confronto terminato: nessuna differenza rilevata. La rete corrisponde al report atteso.\n")
    else:
        print("Confronto terminato: rilevate differenze rispetto al risultato atteso.\n")


#------------------------------------------------------------------------------------------------------------------#


#funzione che salva il report dello scan generando file JSON
def save_results():

    scan_timestamp = datetime.now(ZoneInfo("Europe/Rome"))
    scan_timestamp_str = scan_timestamp.strftime("%d%m%Y_%H%M%S")    # datetime string usata nel nome file di output
    output_scan = f"scan_results_{scan_timestamp_str}.json"

    with open(output_scan, "w") as json_file:
        json.dump(scan_data, json_file, indent=4)
    print(f"File JSON {output_scan} creato con successo!\n")


#---------------------#
#   main del codice   #
#---------------------#
network_discovery() #esegue la network discovery sui subnet target

#verifica se viene trovato almeno un host in una qualsiasi subnet. any controlla che ci sia almeno un dizionario di ip non vuoto
host_trovati = any(scan_data[subnet] for subnet in scan_data)

if host_trovati:
    port_scanning()
    save_results()
    compare_scans()
else:
    print("Nessun host attivo ha risposto ai comandi di network discovery.\n")
    print("Non sono presenti host attivi nella rete o le subnet specificate non sono corrette.\n")
    
print("Script di scansione terminato.")