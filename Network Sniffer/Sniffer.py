import tkinter as tk
from tkinter import scrolledtext
import dns.resolver
import whois
import nmap

# Function to get DNS records
def get_dns_records(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        dns_records = "\n".join([f"IP: {ip}" for ip in result])
    except Exception as e:
        dns_records = f"Error getting DNS records: {e}"
    return dns_records

# Function to get WHOIS records
def get_whois_records(domain):
    try:
        whois_info = whois.whois(domain)
        whois_records = str(whois_info)
    except Exception as e:
        whois_records = f"Error getting WHOIS records: {e}"
    return whois_records

# Function to scan open ports and detect OS
def scan_ports_and_os(ip):
    nm = nmap.PortScanner()
    try:
        # Scan ports from 1 to 1024 and try to detect the OS
        nm.scan(ip, '1-1024', arguments='-O')
        port_info = ""
        
        for host in nm.all_hosts():
            port_info += f"Host: {host} ({nm[host].hostname()})\n"
            port_info += f"State: {nm[host].state()}\n"
            
            # Go through each protocol (TCP/UDP)
            for proto in nm[host].all_protocols():
                port_info += f"Protocol: {proto}\n"
                
                # Extract the list of open ports
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    if state == 'open':  # Only list open ports
                        port_info += f"Port: {port} - State: {state}\n"
            
            # OS Detection
            if 'osclass' in nm[host]:
                for osclass in nm[host]['osclass']:
                    port_info += (f"OS Type: {osclass['osfamily']} - "
                                  f"OS Vendor: {osclass['vendor']} - "
                                  f"OS Accuracy: {osclass['accuracy']}\n")
            else:
                port_info += "OS Detection: Not available\n"
    except Exception as e:
        port_info = f"Error scanning ports: {e}"
    return port_info

# Function to execute the tool and display results
def perform_scan():
    input_value = entry.get().strip()
    
    # Clear previous results
    result_box.delete(1.0, tk.END)
    
    if not input_value:
        result_box.insert(tk.END, "Please enter a valid IP or domain.\n")
        return
    
    # DNS records
    result_box.insert(tk.END, "Fetching DNS Records...\n")
    dns_records = get_dns_records(input_value)
    result_box.insert(tk.END, f"{dns_records}\n\n")
    
    # WHOIS records
    result_box.insert(tk.END, "Fetching WHOIS Records...\n")
    whois_records = get_whois_records(input_value)
    result_box.insert(tk.END, f"{whois_records}\n\n")
    
    # Open ports and OS detection
    result_box.insert(tk.END, "Scanning open ports and OS detection...\n")
    port_info = scan_ports_and_os(input_value)
    result_box.insert(tk.END, f"{port_info}\n\n")

# GUI Setup
root = tk.Tk()
root.title("Network Information Tool")

# Input field
tk.Label(root, text="Enter IP or Domain:").pack(pady=5)
entry = tk.Entry(root, width=50)
entry.pack(pady=5)

# Scan button
scan_button = tk.Button(root, text="Scan", command=perform_scan)
scan_button.pack(pady=5)

# Result display (scrollable text box)
result_box = scrolledtext.ScrolledText(root, height=20, width=80)
result_box.pack(pady=5)

# Run the GUI application
root.mainloop()
