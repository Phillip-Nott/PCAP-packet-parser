# PCAP Parser & Suspicious Traffic Analyzer

A Python tool for parsing `.pcap` files, filtering protocol traffic, exporting data to CSV or PCAP formats, and scanning for suspicious network activity.

## Features
- Parse `.pcap` files into readable summaries
- Filter packets by protocol (HTTP, DNS, etc.)
- Export to CSV for Splunk or spreadsheet tools
- Detect basic suspicious behavior (e.g., SYN scans, ARP probing, spoofing)
- Save filtered traffic back into new `.pcap` files
- uns on Ubuntu via WSL or native Linux

# Setup Guide (WSL + Ubuntu)
## Prerequisites
- WSL installed (Ubuntu 20.04 recommended)
- Wireshark installed in Windows
- Python 3.6+ installed in Ubuntu (check with `python3 --version`)

1. Update System
	sudo apt update && sudo apt upgrade
2. Install Python + Pip 
	sudo apt install python3 python3-pip
3. Install Wireshark CLI 
	sudo apt install tshark
4. Install Python Requirements 
	pip3 install pyshark
5. Capture PCAP (from Wireshark GUI)
    1. Open Wireshark in Windows
    2. Capture traffic, save as .pcap
    3. Move to sample-captures/ folder in WSL
6. Run the Tool 
	python3 pcap_parser.py -f sample-captures/your_file.pcap

## Quick Start
```bash
python3 pcap_parser.py -f sample-captures/capture.pcap -p http -o output/http.csv --export-pcap output/http.pcap --scan

Filter by Protocol

python3 pcap_parser.py -f sample-captures/file.pcap -p http
Export to CSV

python3 pcap_parser.py -f sample-captures/file.pcap -o output/output.csv
Export Filtered Packets to New PCAP

python3 pcap_parser.py -f sample-captures/file.pcap -p dns --export-pcap output/filtered_dns.pcap
Run Suspicious Traffic Scan

python3 pcap_parser.py -f sample-captures/file.pcap --scan
Full Combo Example

python3 pcap_parser.py -f sample-captures/file.pcap -p tcp -o output/tcp.csv --export-pcap output/tcp_filtered.pcap --scan
---

