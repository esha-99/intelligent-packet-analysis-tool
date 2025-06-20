# Intelligent Conversation Monitoring and Threat Detection

##  Project Overview
This tool analyzes network traffic from **pcap files** to extract valuable insights and detect potential cyber threats. It reconstructs **human-readable conversations** between network entities while identifying attacks such as **ARP spoofing, DDoS, SQL injection, and port scanning**.  

## Features
- **Packet Analysis**: Parses and analyzes pcap files using `Tshark` and `Pyshark`.
- **User Details Extraction**: Identifies OS, NIC, and geolocation from network traffic.
- **Readable Conversations**: Converts raw packet data into understandable interactions.
- **Attack Detection**: Identifies cyberattacks based on traffic patterns.
- **Report Generation**: Produces structured security reports.
- **Graphical User Interface (GUI)**: Built using Tkinter for visualization.

## Technologies Used
- **Python**: Core programming language.
- **Tshark**: Packet analysis tool for data extraction.
- **Pyshark**: Python wrapper for `Tshark` to analyze packets.
- **Bash Scripting**: Automates processing and execution.
- **Wireshark**: Used for validation and debugging.
- **Tkinter**: GUI framework for user interaction.

## Methodology
1. **Input**: Accepts pcap files containing network traffic.
2. **Data Extraction**: Uses `Tshark` to retrieve IPs, protocols, and timestamps.
3. **Packet Parsing**: Processes packets with `Pyshark` to infer user details.
4. **Conversation Logic**: Reconstructs interactions between IPs.
5. **Attack Detection**: Identifies unusual traffic behaviors:
   - **DDoS**: Excessive packet flows.
   - **ARP Spoofing**: Inconsistent MAC-IP mappings.
   - **SQL Injection**: Suspicious payloads in HTTP requests.
   - **Port Scan**: Sequential port access patterns.
6. **Output**: Generates readable logs and security reports.

## Challenges and Limitations
- **Processing large pcap files efficiently**.
- **Accurate geolocation mapping from IPs**.
- **Limited detection for encrypted traffic**.
- **Variability in OS/NIC identification accuracy**.
