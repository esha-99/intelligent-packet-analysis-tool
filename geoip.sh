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

# Check if tshark and jq are installed
if ! command -v tshark &> /dev/null; then
    echo "Error: tshark is not installed. Please install it and try again."
    exit 1
fi
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install it and try again."
    exit 1
fi

# Set the directory for reports
REPORT_DIR="$HOME/Desktop/Network Security Final Project/Reports"
REPORT_FILE="$REPORT_DIR/geoip_info_report.html"

# Create the directory if it doesn't exist
mkdir -p "$REPORT_DIR"

echo "Extracting IP addresses and enhancing metadata with GeoIP..."

# Use tshark to extract unique source IP addresses from the pcap file
IP_DATA=$(tshark -r "$PCAP_FILE" -T fields -e ip.src | sort | uniq)

# Output plain text data for Python
{
    echo -e "IP Address\tCountry\tCity\tOrganization"
    while read -r ip; do
        # Fetch geolocation information using ip-api
        geo=$(curl -s "http://ip-api.com/json/$ip" | jq -r '"\(.country),\(.city),\(.org)"')

        # Parse the GeoIP response into separate fields
        country=$(echo "$geo" | cut -d',' -f1)
        city=$(echo "$geo" | cut -d',' -f2)
        org=$(echo "$geo" | cut -d',' -f3)

        # Handle empty or null fields
        country=${country:-"Unknown"}
        city=${city:-"Unknown"}
        org=${org:-"Unknown"}

        # Output as tab-separated values
        echo -e "$ip\t$country\t$city\t$org"
    done <<< "$IP_DATA"
} > "$REPORT_DIR/geoip_plain_output.txt"

# Generate the HTML report
echo "Generating HTML report..."
{
    echo "<!DOCTYPE html>"
    echo "<html lang=\"en\">"
    echo "<head>"
    echo "    <meta charset=\"UTF-8\">"
    echo "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
    echo "    <title>GeoIP Metadata Report</title>"
    echo "    <style>"
    echo "        body { font-family: Arial, sans-serif; margin: 20px; }"
    echo "        table { border-collapse: collapse; width: 100%; }"
    echo "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }"
    echo "        th { background-color: #f4f4f4; }"
    echo "    </style>"
    echo "</head>"
    echo "<body>"
    echo "    <h1>GeoIP Metadata Report</h1>"
    echo "    <table>"
    echo "        <tr><th>IP Address</th><th>Country</th><th>City</th><th>Organization</th></tr>"

    while read -r ip; do
        # Fetch geolocation information using ip-api
        geo=$(curl -s "http://ip-api.com/json/$ip" | jq -r '"\(.country),\(.city),\(.org)"')

        # Parse the GeoIP response into separate fields
        country=$(echo "$geo" | cut -d',' -f1)
        city=$(echo "$geo" | cut -d',' -f2)
        org=$(echo "$geo" | cut -d',' -f3)

        # Handle empty or null fields
        country=${country:-"Unknown"}
        city=${city:-"Unknown"}
        org=${org:-"Unknown"}

        # Add the data to the HTML table
        echo "        <tr><td>$ip</td><td>$country</td><td>$city</td><td>$org</td></tr>"
    done <<< "$IP_DATA"

    echo "    </table>"
    echo "</body>"
    echo "</html>"
} > "$REPORT_FILE"

echo "GeoIP metadata report generated at: $REPORT_FILE"
