#!/bin/bash

# Function to check if the input file exists and is a .pcap file
check_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "Error: File '$file' not found."
        exit 1
    fi

    # Check if the file has a .pcap extension
    if [[ "$file" != *.pcap ]]; then
        echo "Error: '$file' is not a .pcap file."
        exit 1
    fi
}

# Prompt user for a file
read -p "Enter the path to the .pcap file: " PCAP_FILE

# Validate the file
check_file "$PCAP_FILE"

# Notify the user that processing is starting
echo "Running metadata extraction scripts on $PCAP_FILE..."

# Run all the metadata extraction scripts
./mac_ip.sh "$PCAP_FILE"
./ttl.sh "$PCAP_FILE"
./geoip.sh "$PCAP_FILE"
./hardware.sh "$PCAP_FILE"
./attack.sh "$PCAP_FILE"

# Define the output directory and final report path
OUTPUT_DIR="$HOME/Desktop/Network Security Final Project/Reports"
FINAL_REPORT="$OUTPUT_DIR/final_report.html"

# Ensure the output directory exists
mkdir -p "$OUTPUT_DIR"

# Consolidate reports into the final HTML report
echo "<html><head><title>Network Analysis Report</title></head><body>" > "$FINAL_REPORT"
echo "<h1>Network Analysis Report</h1>" >> "$FINAL_REPORT"

# Add MAC and IP information
echo "<pre>$(cat "$OUTPUT_DIR/mac_ip_report.html")</pre>" >> "$FINAL_REPORT"

# Add OS information and TTL values
echo "<pre>$(cat "$OUTPUT_DIR/ttl_report.html")</pre>" >> "$FINAL_REPORT"

# Add GeoIP information
echo "<pre>$(cat "$OUTPUT_DIR/geoip_info_report.html")</pre>" >> "$FINAL_REPORT"

# Add hardware information
echo "<pre>$(cat "$OUTPUT_DIR/hardware_info_report.html")</pre>" >> "$FINAL_REPORT"

# Add ARP spoofing detection report
echo "<pre>$(cat "$OUTPUT_DIR/threat_detection_report.html")</pre>" >> "$FINAL_REPORT"

# Close HTML tags
echo "</body></html>" >> "$FINAL_REPORT"

# Notify the user of completion
echo "Metadata extraction completed. Final report saved to '$FINAL_REPORT'."
