#!/bin/bash

# Check if a file name was provided as an argument
if [ -n "$1" ]; then
    PCAP_FILE="$1"   # Use the provided file name
else
    read -p "Enter the path to the .pcap file: " PCAP_FILE
fi

# Check if the file exists
if [[ ! -f "$PCAP_FILE" ]]; then
    echo "Error: File '$PCAP_FILE' not found."
    exit 1
fi

# Set report paths
REPORT_DIR="$HOME/Desktop/Network Security Final Project/Reports"
PLAIN_TEXT_OUTPUT="$REPORT_DIR/ttl_plain_output.txt"
HTML_OUTPUT="$REPORT_DIR/ttl_report.html"

# Ensure the report directory exists
mkdir -p "$REPORT_DIR"

# Extract TTL values using tshark
PACKET_TTL_DATA=$(tshark -r "$PCAP_FILE" -T fields -e frame.number -e ip.ttl | sort -n)

# Function to determine OS based on TTL
determine_os() {
    local ttl=$1
    case $ttl in
        128) echo "Windows";;
        64) echo "Linux";;
        255) echo "macOS/FreeBSD";;
        200) echo "Cisco Router";;
        50) echo "FreeBSD";;
        100) echo "Solaris";;
        32) echo "AIX";;
        60) echo "Embedded System";;
        30) echo "iOS Device";;
        56) echo "Android Device";;
        55) echo "Smart IoT Device";;
        119) echo "Networking Equipment (Router/Switch)";;
        118) echo "IoT Device or Specialized Equipment";;
        52) echo "Low Power Embedded System";;
        150) echo "Windows Server";;
        110) echo "BSD Variant";;
        61) echo "Smart Appliance";;
        250) echo "Edge Router";;
        45) echo "Mobile Hotspot";;
        80) echo "Virtual Machine (e.g., VMware, Hyper-V)";;
        62) echo "OpenBSD";;
        135) echo "VPN Gateway";;
        90) echo "Enterprise Switch";;
        46) echo "Low-End IoT Device";;
        58) echo "Android Hotspot";;
        107) echo "High-End Router";;
        109) echo "Data Center Equipment";;
        120) echo "Specialized Device (Unknown)";;
        229) echo "Industrial Equipment";;
        53) echo "Unknown IoT Device";;
        1) echo "Corrupted Packet or Malformed Packet";;
        192) echo "Windows Server 2016";;
        148) echo "Solaris";;
        127) echo "Checkpoint Firewall";;
        100) echo "Brocade SAN Switch";;
        154) echo "Juniper Router";;
        115) echo "Arista Switch";;
        176) echo "Dell Networking Switch";;
        94) echo "Fortinet Firewall";;
        225) echo "Industrial IoT Gateway";;
        170) echo "Legacy Cisco Equipment";;
        68) echo "OpenWRT Router";;
        88) echo "Android IoT Gateway";;
        230) echo "RedHat-based IoT Device";;
        105) echo "Juniper MX Series Router";;
        90) echo "HP ProCurve Switch";;
        255) echo "Other Specialized Unix";;
        *) echo "Unknown";; # Default case for unrecognized TTLs
    esac
}

# Output plain text data
{
    echo -e "TTL\tEstimated OS\tPacket Range"
    prev_ttl=""
    start_packet=""
    end_packet=""
    current_os=""

    while read -r packet_number ttl; do
        if [[ -z "$start_packet" ]]; then
            # Initialize the first packet range
            start_packet=$packet_number
            end_packet=$packet_number
            prev_ttl=$ttl
            current_os=$(determine_os "$ttl")
        elif [[ "$ttl" == "$prev_ttl" ]]; then
            # Continue the range if TTL matches the previous
            end_packet=$packet_number
        else
            # Print the range for the previous TTL
            echo -e "$prev_ttl\t$current_os\t${start_packet}-${end_packet}"
            # Start a new range
            start_packet=$packet_number
            end_packet=$packet_number
            prev_ttl=$ttl
            current_os=$(determine_os "$ttl")
        fi
    done <<< "$PACKET_TTL_DATA"

    # Print the last range
    if [[ -n "$start_packet" ]]; then
        echo -e "$prev_ttl\t$current_os\t${start_packet}-${end_packet}"
    fi
} > "$PLAIN_TEXT_OUTPUT"

echo "Plain text TTL output written to $PLAIN_TEXT_OUTPUT."

# Generate HTML report
{
    echo "<!DOCTYPE html>"
    echo "<html lang='en'>"
    echo "<head>"
    echo "    <meta charset='UTF-8'>"
    echo "    <meta name='viewport' content='width=device-width, initial-scale=1.0'>"
    echo "    <title>TTL Report</title>"
    echo "    <style>"
    echo "        body { font-family: Arial, sans-serif; margin: 20px; }"
    echo "        table { border-collapse: collapse; width: 100%; }"
    echo "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }"
    echo "        th { background-color: #f4f4f4; }"
    echo "    </style>"
    echo "</head>"
    echo "<body>"
    echo "    <h1>TTL Analysis Report</h1>"
    echo "    <table>"
    echo "        <tr><th>TTL</th><th>Estimated OS</th><th>Packet Range</th></tr>"

    prev_ttl=""
    start_packet=""
    end_packet=""
    current_os=""

    while read -r packet_number ttl; do
        if [[ -z "$start_packet" ]]; then
            start_packet=$packet_number
            end_packet=$packet_number
            prev_ttl=$ttl
            current_os=$(determine_os "$ttl")
        elif [[ "$ttl" == "$prev_ttl" ]]; then
            end_packet=$packet_number
        else
            echo "        <tr><td>$prev_ttl</td><td>$current_os</td><td>${start_packet}-${end_packet}</td></tr>"
            start_packet=$packet_number
            end_packet=$packet_number
            prev_ttl=$ttl
            current_os=$(determine_os "$ttl")
        fi
    done <<< "$PACKET_TTL_DATA"

    if [[ -n "$start_packet" ]]; then
        echo "        <tr><td>$prev_ttl</td><td>$current_os</td><td>${start_packet}-${end_packet}</td></tr>"
    fi

    echo "    </table>"
    echo "</body>"
    echo "</html>"
} > "$HTML_OUTPUT"

echo "HTML TTL report written to $HTML_OUTPUT."
