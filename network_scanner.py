"""
This script performs a network scan to identify subnets, active hosts, ports, and services
using the python3-nmap (nmap3) library, aiming to map the infrastructure for internship 
analysis activities. If present in the test lab's shared directory, the script also reads 
a .json file to compare the results with the expected scan output.
"""
__author__ = "Stefano Strambi"
__version__ = "1.3.2"



import json
import os
import re
import nmap3
import time
import requests
from datetime import datetime
from zoneinfo import ZoneInfo
from dotenv import load_dotenv

# List of target subnets to scan, defined as strings in CIDR notation (Ipv4 subnet format: "x.x.x.x/x")
TARGET_SUBNETS = []

EXPECTED_JSON = "scan_expected.json"

# Timezone used to generate the timestamp in the output filename (see save_results()).
# Change this value if the lab is run from a different geographical location.
# Must be a valid IANA timezone string (e.g. "UTC"); cannot be left empty.
TIMEZONE = "UTC"

# Absolute path of the directory containing this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")

# Load environment variables from the .env file in the script directory
load_dotenv(os.path.join(SCRIPT_DIR, ".env"))

# API key required for high-rate requests to the database
# Fetch the NIST API key from env variables (defaults to empty string if missing)
NIST_API_KEY = os.environ.get("NIST_API_KEY", "")

# Verify if the API key was successfully loaded and notify the user
if NIST_API_KEY:
    print("\nAPI key successfully loaded for the NVD database scan.\n")
else:
    print("\nWarning: No API key found. NVD database scan will operate under stricter rate limits.\n")


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
    Directly updates details_map with the "os" key and collects all the OS matches
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
    compatible with both 'cpeName' and 'virtualMatchString' request parameters.

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

        # Split at the hyphen (-) ONLY if it is immediately followed by one or more digits (e.g., -1, -2).
        # If it encounters a tilde (~) or a plus sign (+), always split and discard everything after.
        version_clean = re.split(r'-(?=[0-9]+)|[~+]', version)[0]
        
        # Final alphanumeric validation: match the core version pattern and any trailing letters/digits.
        match = re.match(r'^([0-9]+(?:\.[0-9]+)*[a-zA-Z0-9-]*)', version_clean)
        if match:
            parts[3] = match.group(1)
    
    # Truncate the list to keep ONLY the first 4 elements (up to the version field)
    truncated_parts = parts[:4]
        
    return "cpe:2.3:" + ":".join(truncated_parts)



def get_primary_or_first_metric(metric_list):
    """
    This function iterates through a list of CVSS metrics returned by the NVD API and extracts 
    the most accurate evaluation block, prioritizing the official NIST assessment.

    Parameters: 
      - metric_list (list): list of dict containing CVSS metrics.

    Returns:
      - Returns the metric dictionary marked with "type": "Primary" if found.
      - Returns the first metric dictionary (metric_list[0]) as a fallback 
        if no "Primary" authority is explicitly present.
      - Returns None if the provided metric_list is empty, evaluates to False, 
        or is not a valid list instance.
    """
    if not metric_list or not isinstance(metric_list, list):
        return None
        
    for metric in metric_list:
        if metric.get("type") == "Primary":
            return metric
            
    return metric_list[0]



def extract_cvss_metrics(metrics_dict):
    """
    This function parses the NVD metrics dictionary to extract the highest available CVSS score and severity.
    Prioritizes newer versions (V4.0 -> V3.1 -> V3.0 -> V2) and 'Primary' metrics.

    Parameters:
      - metrics_dict (dict): The "metrics" block from an NVD CVE item.

    Returns:
        tuple: A (cvss_score, cvss_severity, cvss_vector) tuple. Defaults to ("N/A", "N/A", "N/A").
    """
    cvss_score = "N/A"
    cvss_severity = "N/A"
    cvss_vector = "N/A"
    
    if "cvssMetricV40" in metrics_dict:
        target_metric = get_primary_or_first_metric(metrics_dict["cvssMetricV40"])
        if target_metric:
            cvss_data_obj = target_metric.get("cvssData", {})
            cvss_score = cvss_data_obj.get("baseScore", "N/A")
            cvss_severity = cvss_data_obj.get("baseSeverity", "N/A")
            cvss_vector   = cvss_data_obj.get("vectorString", "N/A")
            
    elif "cvssMetricV31" in metrics_dict:
        target_metric = get_primary_or_first_metric(metrics_dict["cvssMetricV31"])
        if target_metric:
            cvss_data_obj = target_metric.get("cvssData", {})
            cvss_score = cvss_data_obj.get("baseScore", "N/A")
            cvss_severity = cvss_data_obj.get("baseSeverity", "N/A")
            cvss_vector   = cvss_data_obj.get("vectorString", "N/A")
            
    elif "cvssMetricV30" in metrics_dict:
        target_metric = get_primary_or_first_metric(metrics_dict["cvssMetricV30"])
        if target_metric:
            cvss_data_obj = target_metric.get("cvssData", {})
            cvss_score = cvss_data_obj.get("baseScore", "N/A")
            cvss_severity = cvss_data_obj.get("baseSeverity", "N/A")
            cvss_vector   = cvss_data_obj.get("vectorString", "N/A")
            
    elif "cvssMetricV2" in metrics_dict:
        target_metric = get_primary_or_first_metric(metrics_dict["cvssMetricV2"])
        if target_metric:
            cvss_data_obj = target_metric.get("cvssData", {})
            cvss_score = cvss_data_obj.get("baseScore", "N/A")
            cvss_severity = target_metric.get("baseSeverity", "N/A")
            cvss_vector   = cvss_data_obj.get("vectorString", "N/A")
            
    return cvss_score, cvss_severity, cvss_vector



def extract_cve_references(references_raw):
    """
    This function extracts all available reference links from NVD references
    as a list of objects containing the url and its associated tags.
    Duplicates are removed based on URL.

    Parameters:
      - references_raw (list): Raw list of reference dictionaries from NVD.

    Returns:
        list: A list of dicts, each with "url" (str) and "tags" (list of str).
    """
    if not references_raw:
        return []

    seen_urls = set()
    result = []

    for ref in references_raw:
        url = ref.get("url")
        if not url or url in seen_urls:
            continue

        tags = ref.get("tags", [])
        result.append({"url": url, "tags": tags})
        seen_urls.add(url)

    return result



def get_nist_api_data(url, headers, port_protocol):
    """
    This function executes GET requests (up to max_retries times) to the NIST NVD API.
    Handles network timeouts and server overload errors (429, 503, 504) by 
    implementing an Exponential Backoff retry mechanism.
    
    Parameters:
      - url (str): The full API query URL.
      - headers (dict): HTTP headers including the optional NIST API key.
      - port_protocol (str): The identifier of the active service (e.g., '22/tcp').
        
    Returns:
        dict or None: dictionary on success, None if the request fails after all retries
    """
    max_retries = 5   # Maximum number of retries attempts
    backoff_time = 3  # Initial delay in seconds before the first retry
    
    for attempt in range(max_retries):
        try:
            # HTTP GET request to the NIST NVD API
            # timeout=(10, 60): 10s to establish connection, 60s to wait for server response data
            response = requests.get(url, headers=headers, timeout=(10,60))
            
            # If request was successful return parsed JSON payload immediately
            if response.status_code == 200:
                return response.json()
            
            # Handle Too Many Requests (429), Service Unavailable (503) and Gateway Timeout (504) status codes
            elif response.status_code in (429, 503, 504):
                print(f"      [Attempt {attempt+1}/{max_retries}] NIST API request status code: ({response.status_code}) for {port_protocol}. Retrying in {backoff_time}s...")
                time.sleep(backoff_time)
                backoff_time *= 2  # Double the wait time for the next attempt
                continue
            # Handle permanent errors
            else:
                print(f"      An error occurred while querying the NIST database for {port_protocol}. Status code: {response.status_code}")
                return None
                
        # Handle network layer issues
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            print(f"      [Attempt {attempt+1}/{max_retries}] Network timeout/connection issue for {port_protocol}. Retrying in {backoff_time}s...")
            time.sleep(backoff_time)
            backoff_time *= 2  # Double the wait time for the next attempt
            if attempt == max_retries - 1:
                print(f"      Failed to complete request for {port_protocol} after {max_retries} retries: {e}")
                return None
        
        # Handle unexpected software exceptions
        except Exception as e:
            print(f"      Critical unexpected error for {port_protocol}: {e}")
            return None
    
    print(f"      Error: Failed to obtain a valid response from the GET request for {port_protocol} after {max_retries} attempts.")
    return None



def cve_scan(ip, details_map):
    """
    This function queries the official NIST (NVD) database using the CPE list of the host's active services.
    Requires a 'NIST_API_KEY' saved in the local .env file for faster rate-limited requests to the database.

    Parameters:
      - ip (str): The IP address of the target host;
      - details_map (dict): The dictionary containing the host's details, specifically the "services" key with its associated CPEs.
    """
    services = details_map.get("services", {})

    # Skip CVE scan if no services are available
    if not services:
        return
    
    # Adjust timers and headers based on API key availability
    if NIST_API_KEY:
        headers = {"apiKey": NIST_API_KEY}
        sleep_time = 3
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
            
            # Delegate network logic to our clean simplified helper function
            data = get_nist_api_data(url, headers, port_protocol)
            
            if data is not None:
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
                        
                        # Extract CVSS score and severity using extracted helper function
                        cvss_score, cvss_severity, cvss_vector = extract_cvss_metrics(cve_data.get("metrics", {}))

                        # Extract and prioritize references for the specific CVE using the helper function
                        final_references = extract_cve_references(cve_data.get("references", []))

                        # NIST url link to the specific CVE
                        nist_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                        # Build the CVE details dictionary and append it
                        cve_info = {
                            "cve_id": cve_id,
                            "cvss": cvss_score,
                            "cvss_vector": cvss_vector,
                            "severity": cvss_severity,
                            "summary": cve_desc,
                            "matched_cpe": cpe_converted,
                            "nist_link": nist_link,
                            "references": final_references
                        }
                        service_data["vulnerabilities"].append(cve_info)
                else:
                    print(f"      No CVE detected for '{cpe_converted}' ({port_protocol}).")
                
            # Rate limiting compliance based on NIST guidelines
            time.sleep(sleep_time)
    
    print(f"      CVE scan phase completed for {ip}.\n")


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

    # If both sets are empty: no data to compare, no differences
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

    Parameters:
      - subnets_found (set): Set of subnets identified during the discovery phase.
      - subnets_expected (set): Set of subnets expected from the template configuration.

    Returns:
        bool: True if subnet differences are found, False otherwise.
    """

    return check_diffs(subnets_found, subnets_expected, "New subnet (unexpected)", "Missing subnet")



def compare_hosts(ips_found, ips_expected):
    """
    This function compares discovered active host IPs against the expected ones using check_diffs.

    Parameters:
      - ips_found (set): Set of active host IPs found in a specific subnet.
      - ips_expected (set): Set of expected host IPs for that subnet.

    Returns:
        bool: True if host differences are found, False otherwise.
    """

    return check_diffs(ips_found, ips_expected, "New active host (unexpected)", "Missing host")



def compare_ports(ip, details_found, details_expected):
    """
    This function compares the discovered open ports against the expected ports for a specific host IP.

    Parameters:
      - ip (str): The IP address of the host being compared.
      - details_found (dict): Discovered details dictionary containing the "ports" key.
      - details_expected (dict): Expected details dictionary containing the "ports" key.

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


def save_results():
    """
    This function saves the entire scan_data structure into a timestamped JSON file inside the results directory.
    If the results directory is missing, it creates it accordingly. 
    """

    os.makedirs(RESULTS_DIR, exist_ok=True) # creates "results/" if missing
    os.chmod(RESULTS_DIR, 0o777) # Grant full permissions to the directory

    # Timestamp used in the output filename, generated using the configured TIMEZONE constant.
    scan_timestamp = datetime.now(ZoneInfo(TIMEZONE))
    scan_timestamp_str = scan_timestamp.strftime("%d%m%Y_%H%M%S") # Datetime string used in the output filename
    output_scan = os.path.join(RESULTS_DIR, f"scan_results_{scan_timestamp_str}.json")

    with open(output_scan, "w") as json_file:
        json.dump(scan_data, json_file, indent=4)

    # Grants current user ownership to the generated file
    # Parameters: output file, uid, gid (1000 is assigned to the first real Linux user, change them accordingly to your ids)
    os.chown(output_scan, 1000, 1000) 

    print(f"JSON file {output_scan} successfully created!\n")


#---------------------#
#      MAIN CODE      #
#---------------------#
network_discovery() # Executes network discovery on target subnets

# Verifies if at least one host is found in any subnet.
# 'any' checks if there is at least one non-empty IP dictionary.
hosts_found = any(scan_data[subnet] for subnet in scan_data)

if hosts_found:
    port_scanning()
    save_results()
    compare_scans()
else:
    print("No active hosts responded to the network discovery commands.\n")
    print("Either there are no active hosts on the network or the specified subnets are incorrect.\n")
    
print("Network discovery script finished.")