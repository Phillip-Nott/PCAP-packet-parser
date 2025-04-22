import pyshark
import argparse
import csv
import re
import os

def is_suspicious(packet_fields):
    try:
        protocol = packet_fields[4].lower()
        info = packet_fields[6].lower()
        src_ip = packet_fields[2]
        dst_ip = packet_fields[3]

        # Noisy internal traffic we usually ignore
        NOISY_PROTOCOLS = ['mdns', 'llmnr', 'nbns', 'netbios', 'arp']

        # Suspicious signatures & severity
        if protocol in NOISY_PROTOCOLS:
            if protocol == 'mdns' and 'workgroup' in info:
                return ('mDNS Spoofing', 'Medium')
            if protocol == 'llmnr' and ('is-at' in info or 'who-has' in info):
                return ('LLMNR Name Poisoning', 'Medium')
            if protocol == 'arp' and 'who-has' in info and src_ip != dst_ip:
                return ('ARP Probing', 'Low')
        if '[syn]' in info and 'ack' not in info:
            return ('SYN scan detected', 'Medium')
        if 'dns' in protocol and 'long' in info:
            return ('Suspicious DNS request (long query)', 'High')
        if '91.121.0.0' in info or '185.' in info:
            return ('Suspicious external IP range detected', 'High')

        return None, None

    except Exception as e:
        print(f"⚠️ Error processing packet: {e}")
        return None, None

def parse_pcap(file_path, output_csv=None, protocol=None, export_pcap=None, scan=False):
    print(f"📂 Loading capture: {file_path}")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"No such file: {file_path}")
    
    cap = pyshark.FileCapture(file_path, only_summaries=True)
    filtered_packets = []
    print("🔄 Reading packets...")

    for packet in cap:
        packet_fields = [packet.no, packet.time, packet.source, packet.destination, packet.protocol, packet.length, packet.info]
        if protocol and protocol.lower() not in packet_fields[4].lower():
            continue
        filtered_packets.append(packet_fields)

    if not filtered_packets:
        print("⚠️ No matching packets found.")
    else:
        print(f"✅ Found {len(filtered_packets)} matching packets.")

    # Suspicious packet scanning
    if scan:
        print("🧠 Scanning for suspicious activity...")
        suspicious_packets = []
        for pkt in filtered_packets:
            sig, sev = is_suspicious(pkt)
            if sig:
                suspicious_packets.append({
                    'No.': pkt[0],
                    'Time': pkt[1],
                    'Source': pkt[2],
                    'Destination': pkt[3],
                    'Protocol': pkt[4],
                    'Length': pkt[5],
                    'Info': pkt[6],
                    'Signature': sig,
                    'Severity': sev
                })

        if suspicious_packets:
            print(f"🚨 {len(suspicious_packets)} suspicious packets detected.")
            with open('suspicious_packets.csv', 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=suspicious_packets[0].keys())
                writer.writeheader()
                writer.writerows(suspicious_packets)
            print("💾 Saved suspicious_packets.csv")
        else:
            print("✅ No suspicious packets found.")

    # Save CSV of parsed packets
    if output_csv:
        print(f"💾 Saving parsed packets to {output_csv}")
        with open(output_csv, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
            for pkt in filtered_packets:
                writer.writerow(pkt)
        print("✅ CSV export complete.")

    # Optional export of filtered PCAP
    if export_pcap:
        print(f"📦 Exporting filtered PCAP to: {export_pcap}")
        export_filtered_pcap(file_path, export_pcap, protocol)
        print("✅ Filtered PCAP export complete.")

    cap.close()
    print("✅ Done!")

def export_filtered_pcap(input_pcap, output_pcap, protocol_filter):
    # This requires tshark to be installed
    import subprocess
    display_filter = protocol_filter.lower() if protocol_filter else ''
    try:
        subprocess.run(['tshark', '-r', input_pcap, '-Y', display_filter, '-w', output_pcap], check=True)
    except FileNotFoundError:
        print("⚠️ tshark not found. Install tshark to enable filtered PCAP export.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCAP Parser & Suspicious Scanner")
    parser.add_argument("-f", "--file", required=True, help="Path to .pcap file")
    parser.add_argument("-o", "--output", help="CSV output file name")
    parser.add_argument("-p", "--protocol", help="Filter packets by protocol (e.g., http, dns)")
    parser.add_argument("--export-pcap", help="Export filtered PCAP to file")
    parser.add_argument("--scan", action="store_true", help="Scan for suspicious traffic")

    args = parser.parse_args()

    parse_pcap(
        file_path=args.file,
        output_csv=args.output,
        protocol=args.protocol,
        export_pcap=args.export_pcap,
        scan=args.scan
    )
