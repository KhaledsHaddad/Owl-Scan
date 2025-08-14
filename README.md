# 🦉 OWL-PassiveScan

**Author:** khaled.s.haddad  
**Website:** [khaledhaddad.tech](https://khaledhaddad.tech)  

---

## 🔍 Overview

**OWL-PassiveScan** is a **silent, multi-functional domain reconnaissance tool** for cybersecurity professionals and penetration testers.  
It gathers detailed information about domains without triggering active detection mechanisms.  

---

## ⚙️ Features

- **WHOIS Lookup** – Retrieve domain registration and ownership info  
- **DNS Records Extraction** – Fetch A, AAAA, MX, NS, and TXT records  
- **SSL Certificates (crt.sh)** – Extract public certificate data from crt.sh  
- **IP & Geolocation Info** – Get IP address and approximate location  
- **Partial Page Source Retrieval** – Fetch partial HTML for quick inspection  
- **Port Scanning** – Scan a custom range of ports  
- **Website Screenshot Capture** – Take full-page screenshots via Selenium  

---

## 📦 Requirements

- Python **3.7+**  
- Google Chrome browser  
- ChromeDriver (matching your Chrome version)  
  - Download from: [https://sites.google.com/chromium.org/driver/](https://sites.google.com/chromium.org/driver/)  

### Install Required Python Packages

```bash
pip install -r requirements.txt
