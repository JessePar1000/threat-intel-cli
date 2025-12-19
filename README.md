# Threat Intel CLI

Threat Intel CLI is a command-line tool designed for SOC and Incident Response analysts to perform threat intelligence enrichment on files, hashes, and IP addresses.

It integrates multiple intelligence sources, including VirusTotal, AbuseIPDB, and RDAP, to provide a unified and actionable analysis workflow. When a threat is detected, the tool provides the corresponding URLs from these services for further investigation.

Security note: API keys are automatically read from the system environment, so there is no need to include sensitive credentials in the code.

## Features

- VirusTotal reputation analysis
- AbuseIPDB confidence scoring for IP addresses
- RDAP (Whois replacement) full network reports
- Colored terminal output for readability
- Supports files, hashes, and IP inputs

## Requirements

- Python 3.9+
- VirusTotal API Key
- AbuseIPDB API Key

## Installation

```bash
git clone https://github.com/JessePar1000/threat-intel-cli.git
cd threat-intel-cli
python3 -m pip install -r requirements.txt
```
## Configuration

This tool requires API keys for VirusTotal and AbuseIPDB.
Set them as environment variables before running the script.

### Linux / macOS

```bash
export VT_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
```

### Windows (PowerShell)

```powershell
setx VT_API_KEY "your_virustotal_api_key"
setx ABUSEIPDB_API_KEY "your_abuseipdb_api_key"
```
## Usage

Run the tool by providing a file, hash, or IP address as input.

```powershell
python3 vt_ip_analyzer.py <file | hash | ip>
```

## Examples

```powershell
python3 vt_ip_analyzer.py 8.8.8.8
python3 vt_ip_analyzer.py suspicious_file.exe
python3 vt_ip_analyzer.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```
