import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
import socket
import requests
import whois
import dns.resolver
import threading
import json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import os
import time

def get_ssl_certificates(domain):
    try:
        response = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=10)
        if response.status_code == 200:
            certs = json.loads(response.text)
            unique_names = list({cert['common_name'] for cert in certs if 'common_name' in cert})
            return "\n".join(unique_names)
        else:
            return "No SSL certificates found."
    except Exception as e:
        return f"Error fetching SSL certificates: {e}"

def get_ip_geo(domain):
    try:
        ip = socket.gethostbyname(domain)
        geo = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10).json()
        return f"IP: {ip}\nLocation: {geo.get('city', '')}, {geo.get('country', '')}"
    except Exception as e:
        return f"Error fetching IP/GeoIP: {e}"

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return f"Error fetching WHOIS: {e}"

def get_dns(domain):
    records = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    output = ""
    for record in records:
        try:
            answers = dns.resolver.resolve(domain, record)
            output += f"\n{record} Records:\n"
            for rdata in answers:
                output += f"  {rdata.to_text()}\n"
        except:
            output += f"\n{record} Records: No data found\n"
    return output

def get_source(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        return response.text[:2000]
    except Exception as e:
        return f"Error fetching page source: {e}"

def scan_ports(ip, start_port, end_port, progress_callback=None):
    open_ports = []
    scanned = 0
    total = end_port - start_port + 1

    def scan_port(port):
        nonlocal scanned
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        except:
            pass
        scanned += 1
        if progress_callback:
            progress_callback(scanned, total)

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
    return sorted(open_ports)

def run_scan():
    domain = entry.get().strip()
    if not domain:
        messagebox.showwarning("Warning", "Please enter a domain.")
        return

    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"\U0001F989 Starting passive scan: {domain}\n")
    output_box.insert(tk.END, "-" * 60 + "\n")

    def thread_task():
        results = ""
        results += f"[+] WHOIS:\n{get_whois(domain)}\n\n"
        results += f"[+] DNS Records:\n{get_dns(domain)}\n\n"
        results += f"[+] SSL Certificates (crt.sh):\n{get_ssl_certificates(domain)}\n\n"
        results += f"[+] IP & GeoIP:\n{get_ip_geo(domain)}\n\n"
        results += f"[+] Page Source (partial):\n{get_source(domain)}\n\n"
        output_box.insert(tk.END, results)

    threading.Thread(target=thread_task).start()

def update_progress(scanned, total):
    progress_var.set(int((scanned / total) * 100))

def run_port_scan():
    domain = entry.get().strip()
    if not domain:
        messagebox.showwarning("Warning", "Please enter a domain.")
        return

    try:
        start_port = int(port_start_entry.get())
        end_port = int(port_end_entry.get())
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            messagebox.showwarning("Warning", "Please enter a valid port range (1-65535).")
            return
    except ValueError:
        messagebox.showwarning("Warning", "Port range must be numeric.")
        return

    output_box.insert(tk.END, f"\n\U0001F6A7 Starting port scan on {domain} from port {start_port} to {end_port}...\n")
    output_box.insert(tk.END, "-" * 60 + "\n")

    progress_var.set(0)
    progress_bar.update()

    def thread_task():
        try:
            ip = socket.gethostbyname(domain)
            open_ports = scan_ports(ip, start_port, end_port, progress_callback=update_progress)
            if open_ports:
                result = "Open ports:\n" + "\n".join(str(p) for p in open_ports)
            else:
                result = "No open ports found in the specified range."
            output_box.insert(tk.END, result + "\n\n")
            progress_var.set(100)
        except Exception as e:
            output_box.insert(tk.END, f"Error resolving domain or scanning ports: {e}\n\n")
            progress_var.set(0)

    threading.Thread(target=thread_task).start()

def take_screenshot():
    domain = entry.get().strip()
    if not domain:
        messagebox.showwarning("Warning", "Please enter a domain.")
        return

    options = Options()
    options.headless = True
    options.add_argument("--window-size=1280,720")

    try:
        driver = webdriver.Chrome(options=options)
    except Exception as e:
        messagebox.showerror("Error", f"Error initializing ChromeDriver: {e}")
        return

    output_box.insert(tk.END, f"\n📸 Taking screenshot of http://{domain} ...\n")
    output_box.see(tk.END)

    def thread_task():
        try:
            driver.get(f"http://{domain}")
            time.sleep(3)
            screenshot_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
            if screenshot_path:
                driver.save_screenshot(screenshot_path)
                output_box.insert(tk.END, f"Screenshot saved to {screenshot_path}\n\n")
            else:
                output_box.insert(tk.END, "Screenshot canceled.\n\n")
        except Exception as e:
            output_box.insert(tk.END, f"Error taking screenshot: {e}\n\n")
        finally:
            driver.quit()

    threading.Thread(target=thread_task).start()

def save_results():
    data = output_box.get(1.0, tk.END)
    if not data.strip():
        messagebox.showwarning("Warning", "No data to save.")
        return
    file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file:
        with open(file, "w", encoding="utf-8") as f:
            f.write(data)
        messagebox.showinfo("Saved", f"Results saved to:\n{file}")

root = tk.Tk()
root.title("🦉 OWL-PassiveScan")
root.configure(bg="black")
root.geometry("950x850")

tk.Label(root, text="Enter Domain:", fg="green", bg="black", font=("Courier", 12)).pack(pady=5)
entry = tk.Entry(root, width=50, font=("Courier", 12), bg="black", fg="lime")
entry.pack(pady=5)

tk.Button(root, text="Start Passive Scan", command=run_scan, bg="black", fg="lime", font=("Courier", 12), width=30).pack(pady=10)

frame_ports = tk.Frame(root, bg="black")
frame_ports.pack(pady=10)

tk.Label(frame_ports, text="Port range:", fg="green", bg="black", font=("Courier", 12)).grid(row=0, column=0, padx=5)

port_start_entry = tk.Entry(frame_ports, width=6, font=("Courier", 12), bg="black", fg="lime")
port_start_entry.grid(row=0, column=1, padx=5)
port_start_entry.insert(0, "1")

tk.Label(frame_ports, text="to", fg="green", bg="black", font=("Courier", 12)).grid(row=0, column=2)

port_end_entry = tk.Entry(frame_ports, width=6, font=("Courier", 12), bg="black", fg="lime")
port_end_entry.grid(row=0, column=3, padx=5)
port_end_entry.insert(0, "1024")

tk.Button(root, text="Start Port Scan", command=run_port_scan, bg="black", fg="lime", font=("Courier", 12), width=30).pack(pady=5)

progress_var = tk.IntVar()
progress_bar = ttk.Progressbar(root, orient="horizontal", length=600, mode="determinate", variable=progress_var)
progress_bar.pack(pady=10)

tk.Button(root, text="📸 Take Screenshot", command=take_screenshot, bg="black", fg="lime", font=("Courier", 12), width=30).pack(pady=5)

tk.Button(root, text="💾 Save Results", command=save_results, bg="black", fg="lime", font=("Courier", 12), width=30).pack(pady=5)

output_box = scrolledtext.ScrolledText(root, width=110, height=35, bg="black", fg="lime", font=("Courier", 10))
output_box.pack(pady=10)

footer = tk.Label(root, text="🦉 OWL-PassiveScan | khaled.s.haddad | khaledhaddad.tech", fg="green", bg="black", font=("Courier", 10))
footer.pack(pady=5)

root.mainloop()
