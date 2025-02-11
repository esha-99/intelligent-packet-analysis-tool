import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os  # To extract the filename from the file path
import subprocess  # To call shell scripts dynamically
import importlib.util

global file_loaded, data, mac_ip_data, geoip_data, ttl_data, hardware_data

file_loaded = False
data = {}
mac_ip_data = []
geoip_data = []
ttl_data = []
hardware_data = []


# Load `display_conversation` dynamically from test.py
spec = importlib.util.spec_from_file_location("test", "test.py")
test_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(test_module)
display_conversation = test_module.display_conversation

# Global variable to track if a file has been opened
file_loaded = False
data = {}  # Dictionary to store conversation data dynamically


def run_mac_ip_script(pcap_file):
    """Run mac_ip.sh to fetch MAC and IP data."""
    try:
        # Run the script and capture its stdout
        result = subprocess.run(
            ["bash", "mac_ip.sh", pcap_file],
            capture_output=True,
            text=True
        )
        print("Raw MAC/IP Script Output:\n", result.stdout)  # Debug print

        if result.returncode != 0:
            print(f"Error running mac_ip.sh: {result.stderr}")
            return []

        # Parse MAC/IP data into a dictionary
        mac_ip_data = []
        for line in result.stdout.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) >= 4:
                mac_ip_data.append({
                    "Source MAC": parts[0].strip(),
                    "Source IP": parts[1].strip(),
                    "Destination MAC": parts[2].strip(),
                    "Destination IP": parts[3].strip()
                })
        print("Parsed MAC/IP Data:", mac_ip_data)  # Debug print
        return mac_ip_data
    except Exception as e:
        print(f"Error in run_mac_ip_script: {e}")
        return []

def run_geoip_script(pcap_file):
    """Run geoip.sh to fetch geolocation data."""
    try:
        # Run the script
        result = subprocess.run(
            ["bash", "geoip.sh", pcap_file],
            capture_output=True,
            text=True
        )
        print("GeoIP Script Raw Output:\n", result.stdout)  # Debug print

        if result.returncode != 0:
            print(f"Error running geoip.sh: {result.stderr}")
            return []

        # Read plain text data from the generated file
        geo_data_file = "/home/kali/Desktop/Network Security Final Project/Reports/geoip_plain_output.txt"
        geo_data = []
        with open(geo_data_file, "r") as f:
            lines = f.readlines()
            if not lines:
                print("Error: GeoIP output file is empty.")
                return []
            for i, line in enumerate(lines[1:]):  # Skip the header line
                parts = line.strip().split("\t")
                if len(parts) == 4:
                    geo_data.append({
                        "IP Address": parts[0].strip(),
                        "Country": parts[1].strip() if parts[1].strip() != "null" else "Unknown",
                        "City": parts[2].strip() if parts[2].strip() != "null" else "Unknown",
                        "Organization": parts[3].strip() if parts[3].strip() != "null" else "Unknown"
                    })
                else:
                    print(f"Skipping malformed line {i + 2}: {line.strip()}")
        print("Parsed GeoIP Data:", geo_data)  # Debug print
        return geo_data
    except Exception as e:
        print(f"Error in run_geoip_script: {e}")
        return []


def run_ttl_script(pcap_file):
    """Run ttl.sh to fetch TTL values and OS estimation."""
    try:
        # Run the script
        result = subprocess.run(
            ["bash", "ttl.sh", pcap_file],
            capture_output=True,
            text=True
        )
        print("TTL Script Raw Output:\n", result.stdout)  # Debug print

        if result.returncode != 0:
            print(f"Error running ttl.sh: {result.stderr}")
            return []

        # Define file path
        ttl_output_file = "/home/kali/Desktop/Network Security Final Project/Reports/ttl_plain_output.txt"
        if not os.path.exists(ttl_output_file):
            print(f"TTL output file not found: {ttl_output_file}")
            return []

        # Read and parse the output file
        ttl_data = []
        with open(ttl_output_file, "r") as f:
            lines = f.readlines()[1:]  # Skip the header line
            for line in lines:
                parts = line.strip().split("\t")
                if len(parts) == 3:  # Validate number of fields
                    ttl_data.append({
                        "TTL": parts[0],
                        "Estimated OS": parts[1],
                        "Packet Range": parts[2]
                    })
        print("Parsed TTL Data:", ttl_data)  # Debug print
        return ttl_data

    except FileNotFoundError as fnfe:
        print(f"FileNotFoundError: {fnfe}")
        return []
    except Exception as e:
        print(f"Error in run_ttl_script: {e}")
        return []

def run_hardware_script(pcap_file):
    """Run hardware.sh to fetch hardware and OS information."""
    try:
        result = subprocess.run(
            ["bash", "hardware.sh", pcap_file],
            capture_output=True,
            text=True
        )
        print("Hardware Script Raw Output:\n", result.stdout)  # Debug print

        if result.returncode != 0:
            print(f"Error running hardware.sh: {result.stderr}")
            return []

        # Parse plain text data
        hardware_output_file = "/home/kali/Desktop/Network Security Final Project/Reports/hardware_info_plain_output.txt"
        hardware_data = []
        with open(hardware_output_file, "r") as f:
            lines = f.readlines()[1:]  # Skip the header line
            for line in lines:
                parts = line.strip().split("\t")
                if len(parts) == 4:
                    hardware_data.append({
                        "Source MAC": parts[0],
                        "Source Manufacturer": parts[1],
                        "Destination MAC": parts[2],
                        "Destination Manufacturer": parts[3]
                    })
        print("Parsed Hardware Data:", hardware_data)  # Debug print
        return hardware_data
    except Exception as e:
        print(f"Error in run_hardware_script: {e}")
        return []

def get_manufacturer(mac):
    mac_prefix = ":".join(mac.split(":")[:3]).upper()
    manufacturer_mapping = {
        "00:0C:29": "VMware",
        "44:E9:68": "Cisco Systems",
        # Add more mappings as needed
    }
    return manufacturer_mapping.get(mac_prefix, "Unknown Manufacturer")


def open_file():
    global file_loaded, data, mac_ip_data, geoip_data, ttl_data, hardware_data

    file_path = filedialog.askopenfilename(
        title="Select a file",
        filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")]
    )
    if file_path:
        file_loaded = True
        file_name = os.path.basename(file_path)
        print(f"File selected: {file_name}")

        try:
            # Load conversation data using test.py
            data = display_conversation(file_path)
            print("Conversations Data from test.py:", data)  # Debug print

            # Fetch MAC and GeoIP data
            mac_ip_data = run_mac_ip_script(file_path)
            geoip_data = run_geoip_script(file_path)

            # Integrate MAC and GeoIP into the data dictionary
            for conv_id, conv_values in data.items():
                print(f"Processing Conversation ID: {conv_id}")
                print(f"Initial Conversation Values: {conv_values}")
                src_ip = conv_values[0].split(":")[0]
                dst_ip = conv_values[1].split(":")[0]
                print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

                # Fetch corresponding MAC and GeoIP
                src_mac = next((item["Source MAC"] for item in mac_ip_data if item["Source IP"] == src_ip), "Unknown MAC")
                dst_mac = next((item["Destination MAC"] for item in mac_ip_data if item["Destination IP"] == dst_ip), "Unknown MAC")
                src_geo = next((item for item in geoip_data if item["IP Address"] == src_ip), {"Country": "Unknown", "City": "Unknown", "Organization": "Unknown"})
                dst_geo = next((item for item in geoip_data if item["IP Address"] == dst_ip), {"Country": "Unknown", "City": "Unknown", "Organization": "Unknown"})

                print(f"Source MAC: {src_mac}, Destination MAC: {dst_mac}")
                print(f"Source Geo: {src_geo}, Destination Geo: {dst_geo}")

                # Append the details
                conv_values.append({
                    "Source MAC": src_mac,
                    "Destination MAC": dst_mac,
                    "Source Geo": src_geo,
                    "Destination Geo": dst_geo
                })
                
            # Run ttl.sh
            ttl_data = run_ttl_script(file_path)
            print("TTL data processed successfully!")

            # Run hardware.sh
            hardware_data = run_hardware_script(file_path)
            print("Hardware data processed successfully!")

            print("Updated Conversations Data:", data)  # Debug print
            display_data_in_table()  # Display the updated data in the table
        except Exception as e:
            messagebox.showerror("Processing Error", f"Error processing file: {e}")
    else:
        messagebox.showwarning("No File Selected", "Please select a file.")


def display_data_in_table():
    global data, table, row_frame, table_frame

    if 'row_frame' in globals() and row_frame.winfo_ismapped():
        row_frame.pack_forget()

    if not hasattr(display_data_in_table, "table_created"):
        table_frame = tk.Frame(root)
        table_frame.pack(fill="both", expand=True, pady=10, padx=10)

        columns = ("Serial No", "IP Address 1", "IP Address 2", "Packets")
        table = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        table.pack(fill="both", expand=True)

        style = ttk.Style()
        style.configure("Treeview", font=("Arial", 11), rowheight=30)
        style.configure("Treeview.Heading", font=("Arial", 12, "bold"))

        for col in columns:
            table.heading(col, text=col)
            table.column(col, anchor="center", width=100)

        table.bind("<ButtonRelease-1>", on_row_click)
        display_data_in_table.table_created = True

    table_frame.pack(fill="both", expand=True, pady=10, padx=10)
    for item in table.get_children():
        table.delete(item)

    for sr_no, values in data.items():
        table.insert("", "end", values=(sr_no, values[0], values[1], values[2]))


def on_row_click(event):
    global row_frame, mac_ip_data, hardware_data, geoip_data, table_frame  # Ensure table_frame is declared global
    selected_item = table.selection()
    if selected_item:
        # Extract the row's values
        row_values = table.item(selected_item, "values")
        if row_values:
            print(f"Row clicked: {row_values}")

            # Hide the table frame
            if table_frame:  # Ensure table_frame is not None before calling pack_forget
                table_frame.pack_forget()

            # Create the row detail frame if not already created
            if 'row_frame' not in globals() or row_frame is None:
                row_frame = tk.Frame(root)

            # Clear existing content in the row frame before updating it
            for widget in row_frame.winfo_children():
                widget.destroy()

            # Extract IPs from the selected row
            ip1, port1 = row_values[1].split(":")
            ip2, port2 = row_values[2].split(":")

            # Match and fetch MAC and Manufacturer Data
            source_mac = "Unknown MAC"
            dest_mac = "Unknown MAC"
            source_manufacturer = "Unknown Manufacturer"
            dest_manufacturer = "Unknown Manufacturer"

            for mac_entry in mac_ip_data:
                if mac_entry["Source IP"] == ip1:
                    source_mac = mac_entry["Source MAC"]
                if mac_entry["Destination IP"] == ip2:
                    dest_mac = mac_entry["Destination MAC"]

            # Fetch manufacturers for the MAC addresses
            source_manufacturer = get_manufacturer(source_mac)
            dest_manufacturer = get_manufacturer(dest_mac)

            # Match and fetch GeoIP Data
            source_geo = {"Country": "Unknown", "City": "Unknown", "Organization": "Unknown"}
            dest_geo = {"Country": "Unknown", "City": "Unknown", "Organization": "Unknown"}

            for geo_entry in geoip_data:
                if geo_entry["IP Address"] == ip1:
                    source_geo = geo_entry
                if geo_entry["IP Address"] == ip2:
                    dest_geo = geo_entry

            # Create the row detail layout
            row_frame.pack(fill="both", expand=True, pady=10, padx=10)

            # Create a canvas to represent the layout visually
            canvas = tk.Canvas(row_frame, width=800, height=250)
            canvas.pack(pady=20)

            # Draw the circle for IP1 (A)
            canvas.create_oval(50, 100, 150, 200, fill="#90EE90", outline="")  # Light green for A
            canvas.create_text(100, 150, text="A", font=("Arial", 16, "bold"))

            # Draw the circle for IP2 (B)
            canvas.create_oval(450, 100, 550, 200, fill="#ADD8E6", outline="")  # Light blue for B
            canvas.create_text(500, 150, text="B", font=("Arial", 16, "bold"))

            # Display details for IP1 (A)
            ip1_text = (
                f"IP: {ip1}\n"
                f"MAC: {source_mac}\n"
                f"Manufacturer: {source_manufacturer}\n"
                f"Country: {source_geo['Country']}\n"
                f"City: {source_geo['City']}\n"
                f"Organization: {source_geo['Organization']}"
            )
            canvas.create_text(200, 120, text=ip1_text, font=("Arial", 12), anchor="w")

            # Display details for IP2 (B)
            ip2_text = (
                f"IP: {ip2}\n"
                f"MAC: {dest_mac}\n"
                f"Manufacturer: {dest_manufacturer}\n"
                f"Country: {dest_geo['Country']}\n"
                f"City: {dest_geo['City']}\n"
                f"Organization: {dest_geo['Organization']}"
            )
            canvas.create_text(600, 120, text=ip2_text, font=("Arial", 12), anchor="w")

            # Display the conversation details below the visualization
            conversation_label = tk.Label(row_frame, text="Conversation", font=("Arial", 12, "bold"))
            conversation_label.pack(pady=10, anchor="w", padx=20)  # Padding and anchor for left alignment

            conversation_frame = tk.Frame(row_frame)
            conversation_frame.pack(pady=5, anchor="w", fill="x", padx=20)  # Fill horizontally and align left

            # Display conversation details
            serial_no = int(row_values[0])
            conversation_details = data[serial_no][3]
            for i, detail in enumerate(conversation_details):
                tk.Label(conversation_frame, text=f"{i + 1}. {detail}", font=("Arial", 11), anchor="w").pack(fill="x", padx=20, pady=2)



# Create the main application window
root = tk.Tk()
root.title("PCAP Analysis Tool")
root.geometry("600x400")

menu_bar = tk.Menu(root)
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Open", command=open_file)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)
menu_bar.add_cascade(label="File", menu=file_menu)

menu_bar.add_command(label="Generate Report", command=lambda: print("Report Generated!"))
menu_bar.add_command(label="All Files", command=lambda: print("All Files!"))
menu_bar.add_command(label="All Conversations", command=lambda: display_data_in_table() if file_loaded else messagebox.showwarning("No File", "Load a file first."))

root.config(menu=menu_bar)
root.mainloop()
