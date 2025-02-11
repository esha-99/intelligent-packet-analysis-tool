#!/bin/bash

# Check if a file name was provided as an argument
if [ -n "$1" ]; then
    PCAP_FILE="$1"   # Use the provided file name
else
    # Prompt the user for the .pcap file name if not provided
    read -p "Enter the path to the .pcap file: " PCAP_FILE
fi

# Check if the file exists and has a .pcap extension
if [[ ! -f "$PCAP_FILE" ]]; then
    echo "Error: File '$PCAP_FILE' not found."
    exit 1
elif [[ "${PCAP_FILE##*.}" != "pcap" ]]; then
    echo "Error: '$PCAP_FILE' is not a .pcap file."
    exit 1
fi

# Check if tshark is installed
if ! command -v tshark &> /dev/null; then
    echo "Error: tshark is not installed. Please install it and try again."
    exit 1
fi

# Set the directory for reports
REPORT_DIR="$HOME/Desktop/Network Security Final Project/Reports"
REPORT_FILE="$REPORT_DIR/threat_detection_report.html"

# Create the directory if it doesn't exist
mkdir -p "$REPORT_DIR"

# Start the HTML report
{
    echo "<!DOCTYPE html>"
    echo "<html lang='en'>"
    echo "<head>"
    echo "    <meta charset='UTF-8'>"
    echo "    <meta name='viewport' content='width=device-width, initial-scale=1.0'>"
    echo "    <title>Threat Detection Report</title>"
    echo "    <style>"
    echo "        body { font-family: Arial, sans-serif; margin: 20px; }"
    echo "        h1, h2 { color: #333; }"
    echo "        table { width: 100%; border-collapse: collapse; margin: 20px 0; }"
    echo "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }"
    echo "        th { background-color: #f4f4f4; }"
    echo "    </style>"
    echo "</head>"
    echo "<body>"
    echo "    <h1>Threat Detection Report</h1>"
} > "$REPORT_FILE"

# Function to detect ARP spoofing
detect_arp_spoofing() {
    echo "    <h2>ARP Spoofing Detection</h2>" >> "$REPORT_FILE"
    tshark -r "$PCAP_FILE" -T fields -e eth.src -e arp.src.proto_ipv4 | sort | uniq -d > arp_spoofing.html
    if [[ -s arp_spoofing.html ]]; then
        echo "    <table><tr><th>Source MAC</th><th>Source IP</th></tr>" >> "$REPORT_FILE"
        while read -r line; do
            echo "        <tr><td>${line%%	*}</td><td>${line##*	}</td></tr>" >> "$REPORT_FILE"
        done < arp_spoofing.html
        echo "    </table>" >> "$REPORT_FILE"
    else
        echo "    <p>No ARP spoofing detected.</p>" >> "$REPORT_FILE"
    fi
}

# Function to detect DDoS attacks
detect_ddos() {
    echo "    <h2>DDoS Attack Detection</h2>" >> "$REPORT_FILE"
    tshark -r "$PCAP_FILE" -T fields -e ip.src | sort | uniq -c | sort -nr | awk '$1 > 100 {print $1, $2}' > ddos_ips.html
    if [[ -s ddos_ips.html ]]; then
        echo "    <table><tr><th>Frequency</th><th>IP Address</th></tr>" >> "$REPORT_FILE"
        while read -r count ip; do
            echo "        <tr><td>$count</td><td>$ip</td></tr>" >> "$REPORT_FILE"
        done < ddos_ips.html
        echo "    </table>" >> "$REPORT_FILE"
    else
        echo "    <p>No DDoS attack detected.</p>" >> "$REPORT_FILE"
    fi
}

# Function to detect SQL injection attempts
detect_sql_injection() {
    echo "    <h2>SQL Injection Detection</h2>" >> "$REPORT_FILE"
    tshark -r "$PCAP_FILE" -Y 'tcp contains "SELECT" or tcp contains "INSERT" or tcp contains "UPDATE" or tcp contains "DELETE"' -T fields -e ip.src > sql_injection_attempts.html
    if [[ -s sql_injection_attempts.html ]]; then
        echo "    <table><tr><th>Source IP</th></tr>" >> "$REPORT_FILE"
        while read -r ip; do
            echo "        <tr><td>$ip</td></tr>" >> "$REPORT_FILE"
        done < sql_injection_attempts.html
        echo "    </table>" >> "$REPORT_FILE"
    else
        echo "    <p>No SQL injection attempts detected.</p>" >> "$REPORT_FILE"
    fi
}

# Function to detect Port Scanning
detect_port_scanning() {
    echo "    <h2>Port Scanning Detection</h2>" >> "$REPORT_FILE"
    tshark -r "$PCAP_FILE" -T fields -e ip.src -e tcp.dstport | sort | uniq -c | awk '$1 > 10 {print $1, $2, $3}' > port_scan_ips.html
    if [[ -s port_scan_ips.html ]]; then
        echo "    <table><tr><th>Frequency</th><th>Source IP</th><th>Destination Port</th></tr>" >> "$REPORT_FILE"
        while read -r count src_ip dst_port; do
            echo "        <tr><td>$count</td><td>$src_ip</td><td>$dst_port</td></tr>" >> "$REPORT_FILE"
        done < port_scan_ips.html
        echo "    </table>" >> "$REPORT_FILE"
    else
        echo "    <p>No port scanning detected.</p>" >> "$REPORT_FILE"
    fi
}

# Run all detection functions
detect_arp_spoofing
detect_ddos
detect_sql_injection
detect_port_scanning

# End of HTML Report
{
    echo "</body>"
    echo "</html>"
} >> "$REPORT_FILE"

echo "Threat detection completed. Report saved at: $REPORT_FILE"

