#!/bin/bash

# Input pcap file
PCAP_FILE="capture.pcap"
OUTPUT_FILE="metadata_report.txt"

# Ensure the pcap file exists
if [[ ! -f "$PCAP_FILE" ]]; then
    echo "Error: Pcap file not found!"
    exit 1
fi

# Clear the output file
> "$OUTPUT_FILE"

# Extract MAC addresses and associated IPs
echo "Extracting MAC and IP information..." | tee -a "$OUTPUT_FILE"
tshark -r "$PCAP_FILE" -T fields -e eth.src -e ip.src -e eth.dst -e ip.dst | sort | uniq >> "$OUTPUT_FILE"

# Extract TTL values
echo "Extracting TTL values..." | tee -a "$OUTPUT_FILE"
tshark -r "$PCAP_FILE" -T fields -e ip.ttl | sort | uniq >> "$OUTPUT_FILE"

# Enhance metadata using APIs (e.g., GeoIP)
echo "Enhancing metadata with GeoIP..." | tee -a "$OUTPUT_FILE"
tshark -r "$PCAP_FILE" -T fields -e ip.src | sort | uniq | while read -r ip; do
    geo=$(curl -s "http://ip-api.com/json/$ip" | jq -r '"Country: \(.country), City: \(.city), Org: \(.org)"')
    echo "IP: $ip - Geolocation: $geo" >> "$OUTPUT_FILE"
done

# Detect ARP spoofing attempts
echo "Detecting ARP spoofing attempts..." | tee -a "$OUTPUT_FILE"
tshark -r "$PCAP_FILE" -Y "arp.duplicate-address-detected" >> "$OUTPUT_FILE"

# Summary
echo "Metadata extraction completed. Report saved to $OUTPUT_FILE"
