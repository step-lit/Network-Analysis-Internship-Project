"""
This script performs a network scan to identify subnets, active hosts, ports, and services
using the python3-nmap (nmap3) library, aiming to map the infrastructure for internship 
analysis activities. If present in the test lab's shared directory, the script also reads 
a .json file to compare the results with the expected scan output.
"""
__author__ = "Stefano Strambi"
__version__ = "1.3.1"



import json
import os
import re
import nmap3
import time
import requests
from datetime import datetime
from zoneinfo import ZoneInfo

# List of target subnets to scan, defined as strings in CIDR notation (Ipv4 subnet format: "x.x.x.x/x")
TARGET_SUBNETS = ["110.0.0.0/24","110.0.4.0/24","210.0.3.0/24","10.0.1.0/30","10.0.0.0/30","210.0.4.0/24"]

EXPECTED_JSON = "scan_expected.json"

# Absolute path of the directory containing this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")


# Multi-layered dictionary that stores the network discovery results.
# Structure:
# {
#   "subnet": {
#       "ip_address": {
#           "mac": str, 
#           "os": str, 
#           "ports": list, 
#           "services": { "port/protocol": {"description": str, "cpe": list, "vulnerabilities": list} }
#       }
#   }
# }
scan_data = {}


#------------------------------------------------------------------------------------------------------------------#
# HOST DISCOVERY FUNCTIONS
#------------------------------------------------------------------------------------------------------------------#


def network_discovery():
    """
    This function finds and populates all active subnets and hosts within the network into scan_data.
    """

    print("=================================================================")
    print("||              HOST DISCOVERY: Scan initialized               ||")
    print("=================================================================")

    nmap = nmap3.NmapScanTechniques() # nmap3 library object

    for subnet in TARGET_SUBNETS:
        scan_data[subnet] = {}

        # nmap_ping_scan executes the command "nmap -v -oX -sP subnet";
        # the backward-compatible parameter -sP is used here, 
        # officially replaced by -sn (no port scan) in newer nmap versions;
        result = nmap.nmap_ping_scan(subnet)
        
        for key, value in result.items(): # key: host ip; value: dict of details  

            # Condition to filter and retrieve only active hosts where "state" == "up"
            if isinstance(value, dict) and value.get("state", {}).get("state") == "up":
                ip = key
                print(f"Active host found: {ip}")

                # Extract state info and MAC address for the IP
                state_info = value.get("state", {})
                reason = state_info.get("reason", "")
                mac_info = value.get("macaddress")

                mac_address = "null"

                # If the response comes from the local host, assign 'localhost'
                if reason == "localhost-response":
                    mac_address = "localhost"
                # Otherwise, assign the retrieved MAC address value
                elif mac_info:
                    mac_address = mac_info.get("addr", "null")

                # Initialize the data structure for the discovered IP
                scan_data[subnet][ip] = {
                    "mac": mac_address,
                    "os": "unknown",
                    "ports": [],
                    "services": {},
                }

    print("Host discovery phase completed.\n")


#------------------------------------------------------------------------------------------------------------------#
# PORT SCANNING FUNCTIONS
#------------------------------------------------------------------------------------------------------------------#


def process_ports(host_data, details_map):
    """
    This function processes the port scan, including active services, for a single host.
    Prepares the service map structure for the next CVE scan and directly updates details_map 
    with "ports" and "services" keys.

    Parameters:
      - host_data (dict): The raw results returned by nmap3.scan_top_ports() for the IP;
      - details_map (dict): The target dictionary in scan_data where results will be stored for the IP.
    """

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

        # Discard open|filtered ports as they might represent unresponsive UDP ports
        state = port_info.get("state", "")
        if state == "open|filtered":
            continue
                    
        # Skip the port if the portid key does not contain a string
        if not port_str:
            continue
                    
        port_int = int(port_str)
        open_ports.append(port_int)
        print(f"   -> adding port: {port_int}/{protocol}")

        # Extract service details
        service_info = port_info.get("service", {})
        service_name = service_info.get("name", "")
        service_product = service_info.get("product", "")
        service_version = service_info.get("version", "")
        service_extrainfo = service_info.get("extrainfo", "")

        # Extract CPEs associated with the discovered service port
        extracted_cpes = []
        cpe_list = port_info.get("cpe", [])
        if cpe_list and isinstance(cpe_list, list):
            for cpe_obj in cpe_list:
                cpe_str = cpe_obj.get("cpe")
                if cpe_str:
                    extracted_cpes.append(cpe_str)

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

        # Include both port and protocol in the service string,
        # since a port could be open for both TCP and UDP.
        services_map[f"{port_str}/{protocol}"] = {
            "description": service_desc,
            "cpe": extracted_cpes,
            "vulnerabilities": []
        }

    # Use set() to remove numerical duplicates, ensuring each port is counted 
    # only once if it was discovered under both TCP and UDP protocols.
    details_map["ports"] = sorted(list(set(open_ports)))
    details_map["services"] = services_map



def process_os(host_data, details_map):
    """
    This function processes OS fingerprinting for a single host.
    Directly updates details_map with the "os" key and ollects all the OS matches
    with accuracy >= best_accuracy - tolerance.

    Parameters:
      - host_data (dict): The raw results returned by nmap3.scan_top_ports() for the IP;
      - details_map (dict): The target dictionary in scan_data where results will be stored for the IP.
    """

    os_matches = host_data.get("osmatch", [])

    if not os_matches and isinstance(os_matches, list):
        details_map["os"] = ""
        return

    best_accuracy = int(os_matches[0].get("accuracy", "0"))

    # Accuracy tolerance (includes all OS versions detected within best_accuracy - tolerance)
    tolerance = 2
    min_accepted_accuracy = best_accuracy - tolerance 

    # Collect matches within the tolerance range
    top_matches = [m for m in os_matches if int(m.get("accuracy", "0")) >= min_accepted_accuracy]

                
    # Create a string listing the OS options and their associated accuracy
    os_details_list = []
    for m in top_matches:
        name = m.get("name", "")
        acc = m.get("accuracy", "")
        os_details_list.append(f"{name} ({acc}%)")

    details_map["os"] = " | ".join(os_details_list)
    print(f"   -> OS: {details_map['os']}")



def port_scanning():
    """
    This function executes port scanning, OS fingerprinting and CVE scan for each previously discovered active host.
    """

    print("=================================================================")
    print("||               PORT SCANNING: Scan initialized               ||")
    print("=================================================================")

    nmap = nmap3.Nmap() # nmap3 library object
    
    for ip_map in scan_data.values():

        for ip, details_map in ip_map.items():

            print(f"Scanning open ports and OS fingerprinting on {ip}...")

            # -sS: TCP SYN scan; -sU: UDP scan; -sV: Service version; -O: OS Fingerprinting
            #--open: active ports only; --max-retries, --min-rate: just 1 retry and 1000 packets/s to speed up UDP scan
            result = nmap.scan_top_ports(ip, 1000, args="-sS -sU -sV -O --open -T4 --max-retries 1 --min-rate 1000")

            host_data = result.get(ip, {})

            # Process and extract Nmap scan data to populate ports, services, and OS details for the IP
            process_ports(host_data, details_map)
            process_os(host_data, details_map)

            # Call the CVE scan function
            cve_scan(ip, details_map)

    print("Port scanning phase completed.\n")


#------------------------------------------------------------------------------------------------------------------#
# CVE SCAN FUNCTIONS (NIST NVD DATABASE)
#------------------------------------------------------------------------------------------------------------------#


def cpe_conversion(cpe):
    """
    This function converts a CPE 2.2 string generated by Nmap into the CPE 2.3 short format (6 components),
    compatible with both 'cpeName' and 'virtualStringMatch' request parameters.

    The CPE 2.2 standard URI syntax used by Nmap:
    cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>

    The CPE 2.3 long syntax contains 13 components (including "cpe" and "2.3"):
    cpe : 2.3 : part : vendor : product : version : update : edition : lang : sw_ed : tgt_sw : tgt_hw : other

    Parameters:
      - cpe (str): The 2.2 cpe string to be converted.

    Returns:
        str: The converted short format 2.3 cpe string (without * filling for other components).
    """
    
    # Remove "cpe:/" prefix
    if cpe.startswith("cpe:/"):
        cpe = cpe[5:]
    
    # Split the string by ":" into a parts list
    parts = cpe.split(":")
    
    # If the string contains at least the version field (index 3) and
    # If it's NOT matching any character in the tuple ("*", "-", ""):
    # '*' represents a wildcard (any version);
    # '-' represents NA/Not Applicable (no specific version);
    # ""  represents an empty or unassigned field;
    # In these cases, we preserve them as they are.
    if len(parts) > 3 and parts[3] not in ("*", "-", ""):
        version = parts[3]
        
        match = re.match(r'^([0-9]+(?:\.[0-9]+)*[a-zA-Z]?)', version)
        if match:
            parts[3] = match.group(1)
    
    # Truncate the list to keep ONLY the first 4 elements (up to the version field)
    truncated_parts = parts[:4]
        
    return "cpe:2.3:" + ":".join(truncated_parts)



def cve_scan(ip, details_map):
    """
    This function queries the official NIST (NVD) database using the CPE list of the host's active services.
    Requires an API key for faster rate-limited requests to the database.

    Parameters:
      - ip (str): The IP address of the target host;
      - details_map (dict): The dictionary containing the host's details, specifically the "services" key with its associated CPEs.
    """
    
    services = details_map.get("services", {})

    # Skip CVE scan if no services are available
    if not services:
        return

    # API key required for high-rate requests to the database
    NIST_API_KEY = ""
    
    # Adjust timers and headers based on API key availability
    if NIST_API_KEY:
        headers = {"apiKey": NIST_API_KEY}
        sleep_time = 1
        print(f"   -> Querying official NIST database (Fast mode - API Key enabled) for {ip}...")
    else:
        headers = {}
        sleep_time = 7
        print(f"   -> Querying official NIST database (Slow mode - API Key not enabled) for {ip}...")
    
    for port_protocol, service_data in services.items():
        cpe_list = service_data.get("cpe", [])

        # Skip to next if CPE list is empty
        if not cpe_list:
            continue
            
        for cpe_string in cpe_list:

            # Convert to CPE 2.3 format before querying
            cpe_converted = cpe_conversion(cpe_string)
            print(f"      {cpe_string} found and converted to..")
            print(f"      .. {cpe_converted} (2.3 format).")

            # Skipping CPE 2.3 strings without the version field (at least 4 colons)
            if cpe_converted.count(":") < 5:
                print(f"      Skipping generic CPE '{cpe_converted}' (missing version field).")
                continue

            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString={cpe_converted}"
            
            try:
                response = requests.get(url, headers=headers, timeout=10)
                
                # If the request is successful...
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities_list = data.get("vulnerabilities", [])
                    
                    # If vulnerabilities are found...
                    if vulnerabilities_list:
                        print(f"      Detected {len(vulnerabilities_list)} vulnerabilities for '{cpe_converted}' ({port_protocol})!")
                        
                        for item in vulnerabilities_list:
                            cve_data = item.get("cve", {})
                            cve_id = cve_data.get("id")
                            
                            # Extract the English description
                            descriptions = cve_data.get("descriptions", [])
                            cve_desc = "N/A"
                            for desc in descriptions:
                                if desc.get("lang") == "en":
                                    cve_desc = desc.get("value")
                                    break
                            
                            # Extract CVSS score
                            metrics = cve_data.get("metrics", {})
                            cvss_score = "N/A"
                            
                            # A single CVE can contain multiple scoring versions:
                            # Using an if/elif structure ensures that only the highest/most modern 
                            # available metric is assigned, preventing older scores from overwriting it
                            if "cvssMetricV40" in metrics:
                                cvss_score = metrics["cvssMetricV40"][0].get("cvssData", {}).get("baseScore", "N/A")
                            elif "cvssMetricV31" in metrics:
                                cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "N/A")
                            elif "cvssMetricV30" in metrics:
                                cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", "N/A")
                            elif "cvssMetricV2" in metrics:
                                cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", "N/A")

                            # Build the CVE details dictionary and append it
                            cve_info = {
                                "cve_id": cve_id,
                                "cvss": cvss_score,
                                "summary": cve_desc,
                                "matched_cpe": cpe_converted 
                            }
                            service_data["vulnerabilities"].append(cve_info)
                    
                    else:
                        print(f"      No CVE detected for '{cpe_converted}' ({port_protocol}).")

                else:
                    print(f"      An error occurred while querying the NIST database. Status code: {response.status_code}")
            
            # Handles exceptions if the request fails
            except Exception as e:
                print(f"      Failed to complete request for {port_protocol}: {e}")
                
            # Rate limiting compliance based on NIST guidelines
            time.sleep(sleep_time)


#------------------------------------------------------------------------------------------------------------------#
# SCAN COMPARISON FUNCTIONS (EXPECTED VS ACTUAL RESULTS)
#------------------------------------------------------------------------------------------------------------------#


def check_diffs(set_a, set_b, msg_new, msg_missing):
    """
    This function returns a boolean after checking and printing differences between two sets.

    Parameters:
      - set_a (set): The set containing the discovered/actual values;
      - set_b (set): The set containing the expected values;
      - msg_new (str): The prefix message to print if there are unexpected items in set_a;
      - msg_missing (str): The prefix message to print if items from set_b are missing in set_a.

    Returns:
        bool: True if differences were detected between the two sets, False otherwise.
    """

    new_items = set_a - set_b
    missing_items = set_b - set_a

    # If both sets match and have no differences
    if not set_a and not set_b:
        return False
    
    for item in sorted(new_items):
        print(f"{msg_new}: {item}")
    for item in sorted(missing_items):
        print(f"{msg_missing}: {item}")

    return True



def compare_subnets(subnets_found, subnets_expected):
    """
    This function compares discovered subnets against the expected ones using check_diffs.

    Args:
        subnets_found (set): Set of subnets identified during the discovery phase.
        subnets_expected (set): Set of subnets expected from the template configuration.

    Returns:
        bool: True if subnet differences are found, False otherwise.
    """

    return check_diffs(subnets_found, subnets_expected, "New subnet (unexpected)", "Missing subnet")



def compare_hosts(ips_found, ips_expected):
    """
    This function compares discovered active host IPs against the expected ones using check_diffs.

    Args:
        ips_found (set): Set of active host IPs found in a specific subnet.
        ips_expected (set): Set of expected host IPs for that subnet.

    Returns:
        bool: True if host differences are found, False otherwise.
    """

    return check_diffs(ips_found, ips_expected, "New active host (unexpected)", "Missing host")



def compare_ports(ip, details_found, details_expected):
    """
    This function compares the discovered open ports against the expected ports for a specific host IP.

    Args:
        ip (str): The IP address of the host being compared.
        details_found (dict): Discovered details dictionary containing the "ports" key.
        details_expected (dict): Expected details dictionary containing the "ports" key.

    Returns:
        bool: True if port differences (new or missing) are detected, False otherwise.
    """

    ports_found    = set(details_found.get("ports", []))
    ports_expected = set(details_expected.get("ports", []))
    
    new_ports = ports_found - ports_expected
    missing_ports = ports_expected - ports_found
    
    diffs = False

    if new_ports:
        print(f"New ports detected for {ip}: {sorted(new_ports)}")
        diffs = True
    if missing_ports:
        print(f"Missing/closed ports for {ip}: {sorted(missing_ports)}")
        diffs = True
    return diffs



def compare_scans():
    """
    This function loads the expected JSON template and runs hierarchical comparisons
    (subnets -> hosts -> ports) against the actual scan results.
    """

    print("=================================================================")
    print("||           SCAN COMPARISON: Comparison Initialized           ||")
    print("=================================================================")
    
    expected_json_path = os.path.join(SCRIPT_DIR, EXPECTED_JSON)
    
    # Verify if scan_expected.json exists next to the script
    if not os.path.exists(expected_json_path):
        print(f"Warning: '{EXPECTED_JSON}' file does not exist in the script directory. Cannot perform comparison with the expected scan.\n")
        return
 
    with open(expected_json_path, "r") as f:
        try:
            expected_data = json.load(f) # Data structure retrieved from the expected results file
        except json.JSONDecodeError:
            print(f"Error: '{EXPECTED_JSON}' file not valid.\n")
            return


    subnets_found = set(scan_data.keys())
    subnets_expected = set(expected_data.keys())

    differences_found = compare_subnets(subnets_found, subnets_expected)

    # Analyze common subnets (intersection of sets)
    for sub in sorted(subnets_found.intersection(subnets_expected)):
        map_ips_found = scan_data.get(sub, {})
        map_ips_expected = expected_data.get(sub, {})

        ips_found = set(map_ips_found.keys())
        ips_expected = set(map_ips_expected.keys())

        if compare_hosts(ips_found, ips_expected):
            differences_found = True

        # Analyze common hosts (intersection of sets)
        for ip in sorted(ips_found.intersection(ips_expected)):
            if compare_ports(ip, map_ips_found[ip], map_ips_expected[ip]):
                differences_found = True

    if not differences_found:
        print("Comparison completed: No differences detected. The network matches the expected report.\n")
    else:
        print("Comparison completed: Differences detected compared to the expected report.\n")


#------------------------------------------------------------------------------------------------------------------#


# This function saves the scan report by generating a JSON file
def save_results():
    """
    This function saves the entire scan_data structure into a timestamped JSON file inside the results directory.
    If the results directory is missing, it creates it accordingly. 
    """

    os.makedirs(RESULTS_DIR, exist_ok=True) # creates "results/" if missing
    os.chmod(RESULTS_DIR, 0o777) # Grant full permissions to the directory

    scan_timestamp = datetime.now(ZoneInfo("Europe/Rome"))
    scan_timestamp_str = scan_timestamp.strftime("%d%m%Y_%H%M%S") # Datetime string used in the output filename
    output_scan = os.path.join(RESULTS_DIR, f"scan_results_{scan_timestamp_str}.json")

    with open(output_scan, "w") as json_file:
        json.dump(scan_data, json_file, indent=4)

    # Grants current user ownership to the generated file
    os.chown(output_scan, 1000, 1000) 

    print(f"JSON file {output_scan} successfully created!\n")


#---------------------#
#      MAIN CODE      #
#---------------------#
network_discovery() # Executes network discovery on target subnets

# Verifies if at least one host is found in any subnet.
# 'any' checks if there is at least one non-empty IP dictionary.
host_trovati = any(scan_data[subnet] for subnet in scan_data)

if host_trovati:
    port_scanning()
    save_results()
    compare_scans()
else:
    print("No active hosts responded to the network discovery commands.\n")
    print("Either there are no active hosts on the network or the specified subnets are incorrect.\n")
    
print("Network discovery script finished.")