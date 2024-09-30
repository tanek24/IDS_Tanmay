import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import threading
import psutil
from scapy.all import sniff
import os

# Environment configurations (you can set these as environment variables for flexibility)
interface = os.getenv("NETWORK_INTERFACE", "eth0")  # Default network interface
scan_active = False
captured_data = []

# Function to handle packet sniffing
def capture_packets(packet):
    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        protocol = packet.proto
        packet_info = f"Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol}"
        captured_data.append(packet_info)
        display_output(packet_info)

# Function to start scanning
def start_scan():
    global scan_active
    if not scan_active:
        scan_active = True
        thread = threading.Thread(target=run_sniffing)
        thread.start()
        messagebox.showinfo("Status", "Monitoring Started")
    else:
        messagebox.showwarning("Status", "Monitoring is already running!")

# Function to stop scanning
def stop_scan():
    global scan_active
    if scan_active:
        scan_active = False
        messagebox.showinfo("Status", "Monitoring Stopped")
    else:
        messagebox.showwarning("Status", "Monitoring is not running!")

# Threaded packet sniffer
def run_sniffing():
    while scan_active:
        sniff(prn=capture_packets, iface=interface, store=False, stop_filter=lambda x: not scan_active)

# Monitor system services (network-based)
def monitor_services():
    result = []
    for conn in psutil.net_connections():
        if conn.status == psutil.CONN_ESTABLISHED:
            result.append(f"Service: {conn.laddr}, Status: {conn.status}")
    return "\n".join(result) if result else "No active services"

# Display output in scrollable text area
def display_output(message):
    output_display.config(state=tk.NORMAL)
    output_display.insert(tk.END, message + "\n")
    output_display.yview(tk.END)  # Scroll to the end automatically
    output_display.config(state=tk.DISABLED)

# GUI Setup
root = tk.Tk()
root.title("Intrusion Detection System")
root.geometry("600x400")

# Scrollable output area for displaying packet captures and active services
output_display = scrolledtext.ScrolledText(root, height=12, width=70, state=tk.DISABLED)
output_display.pack(pady=10)

# Start button
start_button = tk.Button(root, text="Start Monitoring", command=start_scan, bg="green", fg="white", width=20)
start_button.pack(pady=10)

# Stop button
stop_button = tk.Button(root, text="Stop Monitoring", command=stop_scan, bg="red", fg="white", width=20)
stop_button.pack(pady=10)

# Show active network services
def show_services():
    services = monitor_services()
    display_output("Active Services:\n" + services)

# Button to display active services
services_button = tk.Button(root, text="Show Active Services", command=show_services, width=20)
services_button.pack(pady=10)

# Save the output to a file
def save_to_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        try:
            with open(file_path, "w") as file:
                file.write("\n".join(captured_data))
            messagebox.showinfo("Success", f"Data saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")

# Save button
save_button = tk.Button(root, text="Save Output to File", command=save_to_file, width=20)
save_button.pack(pady=10)

# Quit button
quit_button = tk.Button(root, text="Quit", command=root.quit, width=20)
quit_button.pack(pady=10)

root.mainloop()
