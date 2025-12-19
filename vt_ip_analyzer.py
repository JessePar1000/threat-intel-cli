#!/usr/bin/env python3
"""
VT-IP-Analyzer

Author: Jesse Alexander
Description:
    CLI tool for threat intelligence analysis of files, hashes and IP addresses.
    Integrates VirusTotal, AbuseIPDB and RDAP to assist SOC and Incident Response
    investigations.

Usage:
    python threat-intel-cli.py <file | hash | ip>

Features:
    - VirusTotal reputation analysis
    - AbuseIPDB confidence scoring
    - RDAP / Whois full report
    - Colored terminal output

Requirements:
    Python:
    - Python 3.9+
    - vt-py
    - requests
    - colorama
    API Keys:
    - Virus Total API
    - AbuseIPDB API

License:
    MIT
"""

# ----------------------------------------
# Libraries
# ----------------------------------------
import vt
import hashlib
import os
import argparse
import ipaddress
import requests
from colorama import Fore, Style, init
init(autoreset=True)

# ----------------------------------------
# Arguments
# ----------------------------------------
parser = argparse.ArgumentParser(
    description = "VirusTotal Scanner (file,hash, IP)"
)
parser.add_argument(
    "target",
    help="File, Hash (MD5, SHA256) or IP Address"
)

args = parser.parse_args()
target = args.target

# ----------------------------------------
# API KEY
# ----------------------------------------
API_KEY = os.getenv("VT_API_KEY") 
if not API_KEY:
    raise RuntimeError("VT_API_KEY is not defined in System")

ABUSE_API_KEY = os.getenv("AIPDB_API_KEY")
if not ABUSE_API_KEY:
    raise RuntimeError("ABUSEIPDB_API_KEY is not defined")

client = vt.Client(API_KEY)

# ----------------------------------------
# Auxiliary Functions
# ----------------------------------------
def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def is_hash(value):
    return len(value) in (32,64) and all(c in "0123456789abcdefABCDEF" for c in value)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# ----------------------------------------
# AbuseIPDB
# ----------------------------------------
def abuseipdb_lookup(ip):
    if not ABUSE_API_KEY:
        raise RuntimeError("ABUSE_API_KEY is not defined in System")
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "key": ABUSE_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }

    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        return r.json()["data"]
    except Exception as e:
        return {"error": str(e)}

# ----------------------------------------
# RDAP
# ----------------------------------------
def extract_contacts(entities):
    contacts = []
    if not entities:
        return contacts

    for entity in entities or []:
        roles = entity.get("roles", []) or []
        vcard = entity.get("vcardArray", []) or []

        email = None
        if len(vcard) == 2:
            for item in vcard[1]:
                if item[0] == "email":
                    email = item[3]

        contacts.append({
            "roles": roles,
            "email": email
        })

    return contacts

def rdap_lookup(ip): #RDAP Function
    try:
        r = requests.get(
            f"https://rdap.arin.net/registry/ip/{ip}",
            timeout=10
        )
        r.raise_for_status()
        data = r.json()

        report = {
            "name": data.get("name"),
            "handle": data.get("handle"),
            "start": data.get("startAddress"),
            "end": data.get("endAddress"),
            "country": data.get("country"),
            "parent": data.get("parentHandle"),
            "cidr": None,
            "registered": None,
            "entities": extract_contacts(data.get("entities")),
            "remarks": []
        }

        for event in data.get("events") or []:
            if event.get("eventAction") == "registration":
                report["registered"] = event.get("eventDate")

        for cidr in data.get("cidr0_cidrs") or []:
            if cidr.get("v4prefix") and cidr.get("length") is not None:
                report["cidr"] = f"{cidr['v4prefix']}/{cidr['length']}"

        for remark in data.get("remarks") or []:
            for line in remark.get("description") or []:
                report["remarks"].append(line)

        return report

    except Exception as e:
        return {"error": str(e)}

# ----------------------------------------
# Main Logic
# ----------------------------------------
try:
    obj = None
    vt_url = None
    sha256 = None
    vt_maliciousF = None
    vt_maliciousIP = None
    vt_maliciousH = None

    #CASE 1: FILE
    if os.path.isfile(target):
        print(Fore.CYAN + "File Detected")
        file_hash = sha256_file(target)
        obj = client.get_object(f"/files/{file_hash}")
        stats = getattr(obj, "last_analysis_stats", None)
        vt_url = f"https://www.virustotal.com/gui/file/{file_hash}"  
        vt_maliciousF = False
        
        if stats:
            vt_maliciousF = (
            stats.get("malicious", 0) > 0 or
            stats.get("suspicious", 0) > 0
            )
    
    #CASE 2: IP ADDRESS
    elif is_ip(target):
        print(Fore.CYAN + "[*] IP Address Detected")

        #VirusTotal
        obj = client.get_object(f"/ip_addresses/{target}")
        stats = getattr(obj, "last_analysis_stats", None)
        vt_url = f"https://www.virustotal.com/gui/ip-address/{target}"
        vt_maliciousIP = False

        if stats:
            vt_maliciousIP = (
            stats.get("malicious", 0) > 0 or
            stats.get("suspicious", 0) > 0
            )

        #AbuseIPDB
        print(Fore.CYAN + "\n[*] AbuseIPDB Report:")
        abuse = abuseipdb_lookup(target)

        abuse_score = abuse.get("abuseConfidenceScore", 0)
        total_reports = abuse.get("totalReports", 0)

        print(f"   Abuse Confidence Score: {abuse.get('abuseConfidenceScore')}%")
        print(f"   Total Reports: {abuse.get('totalReports')}")
        print(f"   Last Reported: {abuse.get('lastReportedAt')}")
        print(f"   ISP: {abuse.get('isp')}")
        print(f"   Usage Type: {abuse.get('usageType')}")
        print(f"   Country: {abuse.get('countryName')}")

        abuse_malicious = abuse_score > 0
        if abuse_malicious:
            abuse_url = f"https://www.abuseipdb.com/check/{target}"
            print(f"   AbuseIPDB Link: {Fore.BLUE}{abuse_url}{Style.RESET_ALL}")

        #RDAP
        if abuse_malicious:
            print(Fore.CYAN + "\n[*] RDAP Full Report:")
            rdap = rdap_lookup(target)

            if "error" in rdap:
                print(f"   RDAP Error: {rdap['error']}")
            else:
                print(f"   Network Name: {rdap.get('name')}")
                print(f"   CIDR: {rdap.get('cidr')}")
                print(f"   Range: {rdap.get('start')} - {rdap.get('end')}")
                print(f"   Country: {rdap.get('country')}")
                print(f"   Registered: {rdap.get('registered')}")

                if rdap.get("entities"):
                    print("\n   Contacts:")
                    for c in rdap["entities"]:
                        roles = ", ".join(c.get("roles") or [])
                        if roles:
                            print(f"     - Roles: {roles}")
                        if c.get("email"):
                            print(f"       Email: {c.get('email')}")
                
                rdap_url = f"https://search.arin.net/rdap/?query={target}"
                print(f"\nWhois / RDAP Link: {Fore.BLUE}{rdap_url}{Style.RESET_ALL}")

    #CASE 3: Hash
    elif is_hash(target):
        print(Fore.CYAN + "[*] Hash Detected")
        obj = client.get_object(f"/files/{target}")
        sha256 = obj.id #SHA256
        stats = getattr(obj, "last_analysis_stats", None)
        vt_url = f"https://www.virustotal.com/gui/file/{sha256}"
        vt_maliciousH = False

        if stats:
            vt_maliciousH = (
            stats.get("malicious", 0) > 0 or
            stats.get("suspicious", 0) > 0
            )
    
    else:
        print("[-] Not Valid Input")
        exit(1)

# ----------------------------------------
# Analysis Results
# ----------------------------------------
    stats = getattr(obj, "last_analysis_stats", None)

    print(Fore.CYAN + "\n[*] VirusTotal Analysis Stats:")
    if not stats:
        print("   No analysis stats available")
        threat = False
    else:
        for k, v in stats.items():
            print(f"   {k}: {v}")
        threat = stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0

    if threat:
        print(Fore.RED +"\n[!] Threat Detected!")
    else:
        print(Fore.GREEN +"\n[+] No Threats Detected")
    if vt_maliciousF or vt_maliciousIP or vt_maliciousH:
            print(f"\nVirusTotal Link: {Fore.BLUE}{vt_url}{Style.RESET_ALL}")
 
finally:
    client.close()
