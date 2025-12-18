# Threat Intel CLI

Threat Intel CLI is a command-line tool designed for SOC and Incident Response
analysts to perform threat intelligence enrichment on files, hashes, and IP
addresses.

It integrates multiple intelligence sources to provide a unified and
actionable analysis workflow.

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

# Linux / macOS
