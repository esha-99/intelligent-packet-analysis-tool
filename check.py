import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import subprocess


class PCAPAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PCAP Analysis Tool")
        self.root.geometry("900x600")
        self.file_path = None

        # Create main interface
        self.create_widgets()

    def create_widgets(self):
        # File selection
        self.file_frame = ttk.LabelFrame(self.root, text="Select PCAP File")
        self.file_frame.pack(fill="x", padx=10, pady=5)

        self.file_label = ttk.Label(self.file_frame, text="No file selected")
        self.file_label.pack(side="left", padx=5)

        self.browse_button = ttk.Button(self.file_frame, text="Browse", command=self.select_file)
        self.browse_button.pack(side="right", padx=5)

        # Tabs for displaying data
        self.tab_control = ttk.Notebook(self.root)
        self.mac_ip_tab = ttk.Frame(self.tab_control)
        self.geoip_tab = ttk.Frame(self.tab_control)
        self.ttl_tab = ttk.Frame(self.tab_control)
        self.hardware_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.mac_ip_tab, text="MAC/IP Data")
        self.tab_control.add(self.geoip_tab, text="GeoIP Data")
        self.tab_control.add(self.ttl_tab, text="TTL Data")
        self.tab_control.add(self.hardware_tab, text="Hardware Data")

        self.tab_control.pack(expand=1, fill="both", padx=10, pady=5)

        # Run Analysis button
        self.run_button = ttk.Button(self.root, text="Run Analysis", command=self.run_analysis)
        self.run_button.pack(pady=10)

    def select_file(self):
        self.file_path = filedialog.askopenfilename(
            title="Select a PCAP File",
            filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")]
        )
        if self.file_path:
            self.file_label.config(text=os.path.basename(self.file_path))
        else:
            self.file_label.config(text="No file selected")

    def run_script(self, script_name):
        try:
            result = subprocess.run(
                ["bash", script_name, self.file_path],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                raise Exception(result.stderr)
            return result.stdout
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run {script_name}:\n{e}")
            return None

    def parse_output(self, output, columns, parent_frame):
        for widget in parent_frame.winfo_children():
            widget.destroy()

        if not output:
            ttk.Label(parent_frame, text="No data available").pack()
            return

        tree = ttk.Treeview(parent_frame, columns=columns, show="headings")
        tree.pack(expand=1, fill="both")

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, anchor="center", width=150)

        for line in output.strip().split("\n")[1:]:  # Skip header line
            tree.insert("", "end", values=line.split("\t"))

    def run_analysis(self):
        if not self.file_path:
            messagebox.showwarning("Warning", "Please select a PCAP file first.")
            return

        # Run each script and display the results
        mac_ip_output = self.run_script("mac_ip.sh")
        geoip_output = self.run_script("geoip.sh")
        ttl_output = self.run_script("ttl.sh")
        hardware_output = self.run_script("hardware.sh")

        # Parse and display output in respective tabs
        if mac_ip_output:
            self.parse_output(mac_ip_output, ["Source MAC", "Source IP", "Destination MAC", "Destination IP"], self.mac_ip_tab)
        if geoip_output:
            self.parse_output(geoip_output, ["IP Address", "Country", "City", "Organization"], self.geoip_tab)
        if ttl_output:
            self.parse_output(ttl_output, ["TTL", "Estimated OS", "Packet Range"], self.ttl_tab)
        if hardware_output:
            self.parse_output(hardware_output, ["Source MAC", "Source Manufacturer", "Destination MAC", "Destination Manufacturer"], self.hardware_tab)


if __name__ == "__main__":
    root = tk.Tk()
    app = PCAPAnalyzerGUI(root)
    root.mainloop()
