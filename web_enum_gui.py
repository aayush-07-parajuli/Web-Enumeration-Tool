import requests
import whois
import socket
import sqlite3
import csv
import dns.resolver
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# Database Setup
conn = sqlite3.connect("web_enum_results.db")
cursor = conn.cursor()

# Ensure table has all required columns
cursor.execute("""
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    subdomains TEXT,
    directories TEXT,
    http_headers TEXT,
    whois_info TEXT,
    open_ports TEXT,
    dns_records TEXT  -- Ensure this column exists
)
""")
conn.commit()

# GUI Setup
root = tk.Tk()
root.title("Automated Web Enumeration Tool")
root.geometry("750x600")

subdomains = ["admin", "mail", "blog", "test", "dev", "shop"]
directories = ["admin", "login", "dashboard", "uploads", "config"]

def enumerate_subdomains(domain):
    subdomain_results = []
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                subdomain_results.append(url)
        except requests.exceptions.RequestException:
            pass
    return ", ".join(subdomain_results) if subdomain_results else "None found"

def enumerate_directories(domain):
    directory_results = []
    for directory in directories:
        url = f"http://{domain}/{directory}/"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                directory_results.append(url)
        except requests.exceptions.RequestException:
            pass
    return ", ".join(directory_results) if directory_results else "None found"

def analyze_http_headers(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=2)
        headers = response.headers
        return "\n".join([f"{header}: {value}" for header, value in headers.items()])
    except requests.exceptions.RequestException:
        return "Unable to fetch headers."


def perform_whois_lookup(domain):
    """Performs WHOIS lookup for domain information."""
    try:
        domain_info = whois.query(domain)  # Ensure you are using whois.query()
        return f"Domain: {domain_info.name}\nRegistrar: {domain_info.registrar}\nCreated: {domain_info.creation_date}\nExpires: {domain_info.expiration_date}"
    except Exception:
        return "WHOIS lookup failed."


def scan_ports(domain):
    common_ports = [21, 22, 23, 25, 53, 80, 443, 8080]
    ip = socket.gethostbyname(domain)
    open_ports = []

    def check_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((ip, port)) == 0:
            open_ports.append(str(port))
        sock.close()

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(check_port, common_ports)

    return ", ".join(open_ports) if open_ports else "No open ports found"

def perform_dns_lookup(domain):
    record_types = ["A", "CNAME", "MX", "TXT"]
    dns_results = []
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            for answer in answers:
                dns_results.append(f"{record}: {answer.to_text()}")
        except:
            pass
    return "\n".join(dns_results) if dns_results else "No DNS records found"

def start_enumeration():
    domain = entry_domain.get()
    if not domain:
        messagebox.showerror("Error", "Please enter a valid domain!")
        return
    
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, "[+] Starting enumeration...\n")
    root.update()

    with ThreadPoolExecutor() as executor:
        subdomains = executor.submit(enumerate_subdomains, domain).result()
        directories = executor.submit(enumerate_directories, domain).result()
        headers = executor.submit(analyze_http_headers, domain).result()
        whois_info = executor.submit(perform_whois_lookup, domain).result()
        open_ports = executor.submit(scan_ports, domain).result()
        dns_records = executor.submit(perform_dns_lookup, domain).result()

    results = f"""
    Subdomains:\n{subdomains}
    \nDirectories:\n{directories}
    \nHTTP Headers:\n{headers}
    \nWHOIS Information:\n{whois_info}
    \nOpen Ports:\n{open_ports}
    \nDNS Records:\n{dns_records}
    """
    text_output.insert(tk.END, results)
    text_output.insert(tk.END, "\n[✔] Enumeration Completed!\n")

    cursor.execute("INSERT INTO results (domain, subdomains, directories, http_headers, whois_info, open_ports, dns_records) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (domain, subdomains, directories, headers, whois_info, open_ports, dns_records))
    conn.commit()

def export_to_csv():
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return
    cursor.execute("SELECT * FROM results")
    rows = cursor.fetchall()
    with open(file_path, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["ID", "Domain", "Subdomains", "Directories", "HTTP Headers", "WHOIS Info", "Open Ports", "DNS Records"])
        writer.writerows(rows)
    messagebox.showinfo("Export Successful", f"Results saved to {file_path}")

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="Enter Target Domain:", font=("Arial", 12)).grid(row=0, column=0)
entry_domain = tk.Entry(frame, font=("Arial", 12), width=30)
entry_domain.grid(row=0, column=1)
tk.Button(frame, text="Start Scan", font=("Arial", 12), command=start_enumeration).grid(row=0, column=2)
tk.Button(root, text="Export to CSV", font=("Arial", 12), command=export_to_csv).pack(pady=5)

text_output = scrolledtext.ScrolledText(root, font=("Arial", 10), width=80, height=20)
text_output.pack(pady=10)

root.mainloop()
