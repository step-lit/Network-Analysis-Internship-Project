"""
Questo script esegue una scansione di rete per identificare le subnet, gli host attivi e 
le porte attive utilizzando i comandi ping (iputils) ed nc (netcat), al fine di mappare
l'infrastruttura per le attivita' di analisi del tirocinio.
"""
__author__ = "Stefano Strambi"
__version__ = "1.0"



import ipaddress
import subprocess

TARGET_SUBNETS = ["110.0.0.0/24","110.0.4.0/24","210.0.3.0/24","10.0.1.0/30","10.0.0.0/30","210.0.4.0/24"] #definisco le subnet per il lab type_3
PORT_RANGE = "80-9000"
OUTPUT_FILE = "scan_results.txt"

#funzione che ritorna un array di stringhe (ip attivi)
def network_discovery():
    active_ips = [] #array per contenere gli ip (attivi) trovati

    print("Fase di Network Discovery iniziata...")

    for subnet in TARGET_SUBNETS:
        network = ipaddress.ip_network(subnet)
        
        for ip in network.hosts():
            ip_string = str(ip)

            result = subprocess.run(["ping", "-c", "1", "-W", "0.2", ip_string])

            if result.returncode == 0:
                print("Nuovo ip trovato! Lo aggiungo alla lista degli ip...")
                active_ips.append(ip_string)

    print("Fase di Network Discovery terminata.")

    return active_ips


#funzione che genera un array di stringhe contenente i risultati del comando nc per ogni ip
def port_scanning(ip_list): 
    nc_reports = [] #array per contenere i report di nc

    print("Inizio del port scanning...")

    for ip in ip_list:

        print(f"Controllo porte aperte su: {ip}")

        nc_command = f"nc -zv -w 1 {ip} {PORT_RANGE}"
        result = subprocess.run(nc_command, shell=True, capture_output=True, text=True)

        full_result = result.stdout + result.stderr

        for row in full_result.splitlines():
            if "succeeded" in row:
                print(f"Trovate porte aperte su {ip}!")
                print(f"Aggiungo le porte al file di report...")
                nc_reports.append(row + "\n")

    print("Fine del port scanning...")
    return nc_reports


#funzione che salva su un file di testo il ri
def save_results(active_ips, scan_reports):

    with open(OUTPUT_FILE, "w") as f:
        f.write("==========================================\n")
        f.write("========== NETWORK DISCOVERY =============\n")
        f.write("==========================================\n")
        f.write("\n\n")

        f.write("========== HOST ATTIVI TROVATI ===========\n")
        if not active_ips:
            f.write("Nessun host attivo rilevato.\n")

        for ip in active_ips:
            f.write(f"{ip}\n")
        f.write("\n\n")

        f.write("========= PORTE ATTIVE PER HOST ==========\n")
        if not scan_reports:
            f.write("Nessuna porta aperta sugli host attivi.\n")
        else:
            for report in scan_reports:
                    f.write(report)
                    f.write("-" * 42 + "\n")


hosts_trovati = network_discovery() #esegue la network discovery sui subnet target

if hosts_trovati: #se la lista di host non e' vuota, viene eseguito il port scanning
    report_finale = port_scanning(hosts_trovati) #esegue lo scan delle porte su ogni host trovato
    save_results(hosts_trovati, report_finale) #salva su file
else:
    print("Nessun host attivo ha risposto ai comandi di network discovery. Scansione interrotta.")

print("Scanning terminato. Verificare la presenza del file scan_results.txt nella cartella shared del lab.")    