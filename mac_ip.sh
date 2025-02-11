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

# Set the directory for reports
REPORT_DIR="/home/kali/Desktop/Network Security Final Project/Reports"
REPORT_FILE="$REPORT_DIR/mac_ip_report.html"

# Create the directory if it doesn't exist
mkdir -p "$REPORT_DIR"

# Extract MAC and IP information
echo "Extracting MAC and IP information from $PCAP_FILE..."
MAC_IP_DATA=$(tshark -r "$PCAP_FILE" -T fields -e eth.src -e ip.src -e eth.dst -e ip.dst | sort | uniq)

# Output plain text data for Python to capture
echo "$MAC_IP_DATA"

# Generate the HTML report
echo "Generating HTML report..."
{
    echo "<!DOCTYPE html>"
    echo "<html lang=\"en\">"
    echo "<head>"
    echo "    <meta charset=\"UTF-8\">"
    echo "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
    echo "    <title>MAC and IP Report</title>"
    echo "    <style>"
    echo "        body { font-family: Arial, sans-serif; margin: 20px; }"
    echo "        table { border-collapse: collapse; width: 100%; }"
    echo "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }"
    echo "        th { background-color: #f4f4f4; }"
    echo "    </style>"
    echo "</head>"
    echo "<body>"
    echo "    <h1>MAC and IP Address Report</h1>"
    echo "    <table>"
    echo "        <tr><th>Source MAC</th><th>Source IP</th><th>Destination MAC</th><th>Destination IP</th></tr>"

    # Populate the table with extracted data
    while IFS=$'\t' read -r src_mac src_ip dst_mac dst_ip; do
        echo "        <tr><td>$src_mac</td><td>$src_ip</td><td>$dst_mac</td><td>$dst_ip</td></tr>"
    done <<< "$MAC_IP_DATA"

    echo "    </table>"
    echo "</body>"
    echo "</html>"
} > "$REPORT_FILE"

echo "MAC and IP information report generated at: $REPORT_FILE"
