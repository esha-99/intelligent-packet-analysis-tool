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
HTML_REPORT_FILE="$REPORT_DIR/hardware_info_report.html"
TXT_REPORT_FILE="$REPORT_DIR/hardware_info_report.txt"

# Create the directory if it doesn't exist
mkdir -p "$REPORT_DIR"

echo "Extracting MAC addresses and hardware information from $PCAP_FILE..."

# Use tshark to extract and resolve MAC addresses
MAC_DATA=$(tshark -r "$PCAP_FILE" -T fields -e eth.src -e eth.src_resolved -e eth.dst -e eth.dst_resolved | sort | uniq)

# Generate the TXT report
echo "Generating TXT report..."
{
    echo "Hardware Information Report"
    echo "==========================="
    echo -e "Source MAC\tSource Manufacturer\tDestination MAC\tDestination Manufacturer"
    while read -r line; do
        src_mac=$(echo "$line" | awk '{print $1}')
        src_manufacturer=$(echo "$line" | awk '{print $2}')
        dst_mac=$(echo "$line" | awk '{print $3}')
        dst_manufacturer=$(echo "$line" | awk '{print $4}')

        # Replace unresolved names with "Unknown Manufacturer"
        [ "$src_manufacturer" == "(none)" ] && src_manufacturer="Unknown Manufacturer"
        [ "$dst_manufacturer" == "(none)" ] && dst_manufacturer="Unknown Manufacturer"

        # Skip empty or invalid lines
        if [ -z "$src_mac" ] || [ -z "$dst_mac" ]; then
            continue
        fi

        echo -e "$src_mac\t$src_manufacturer\t$dst_mac\t$dst_manufacturer"
    done <<< "$MAC_DATA"
} > "$TXT_REPORT_FILE"

# Generate the HTML report
echo "Generating HTML report..."
{
    echo "<!DOCTYPE html>"
    echo "<html lang=\"en\">"
    echo "<head>"
    echo "    <meta charset=\"UTF-8\">"
    echo "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
    echo "    <title>Hardware Information Report</title>"
    echo "    <style>"
    echo "        body { font-family: Arial, sans-serif; margin: 20px; }"
    echo "        table { border-collapse: collapse; width: 100%; }"
    echo "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }"
    echo "        th { background-color: #f4f4f4; }"
    echo "    </style>"
    echo "</head>"
    echo "<body>"
    echo "    <h1>Hardware Information Report</h1>"
    echo "    <table>"
    echo "        <tr><th>Source MAC</th><th>Source Manufacturer</th><th>Destination MAC</th><th>Destination Manufacturer</th></tr>"

    # Populate the table with MAC addresses and resolved manufacturer names
    while read -r line; do
        src_mac=$(echo "$line" | awk '{print $1}')
        src_manufacturer=$(echo "$line" | awk '{print $2}')
        dst_mac=$(echo "$line" | awk '{print $3}')
        dst_manufacturer=$(echo "$line" | awk '{print $4}')

        # Replace unresolved names with "Unknown Manufacturer"
        [ "$src_manufacturer" == "(none)" ] && src_manufacturer="Unknown Manufacturer"
        [ "$dst_manufacturer" == "(none)" ] && dst_manufacturer="Unknown Manufacturer"

        # Skip empty or invalid lines
        if [ -z "$src_mac" ] || [ -z "$dst_mac" ]; then
            continue
        fi

        echo "        <tr><td>$src_mac</td><td>$src_manufacturer</td><td>$dst_mac</td><td>$dst_manufacturer</td></tr>"
    done <<< "$MAC_DATA"

    echo "    </table>"
    echo "</body>"
    echo "</html>"
} > "$HTML_REPORT_FILE"

echo "Hardware information reports generated:"
echo "  - TXT report: $TXT_REPORT_FILE"
echo "  - HTML report: $HTML_REPORT_FILE"
