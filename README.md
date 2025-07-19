# 🛡️ MVTRACK - Malware & Vulnerability Tracker

**MVTRACK** is a powerful, cross-platform malware and vulnerability analysis framework designed for red teams, blue teams, security researchers, and malware analysts. It detects obfuscated malware, analyzes threats, scans for vulnerabilities, and provides real-time red alerting.

---

## 🚀 Features

- ✅ **Multi-layered Encoded Malware Detection**
  - Base64, Hex, ROT13, URL-encoded, and double/triple encoding detection

- 🔍 **YARA Rule Matching**
  - Scan files against custom or global YARA rules

- 🧠 **Reverse Shell Detection**
  - Detects common reverse shell payloads in scripts or binaries

- 💣 **Webshell Fingerprinting**
  - Identifies common PHP/ASP webshell code

- 🧬 **Malware Encoder Detection**
  - Detects msfvenom-encoded or obfuscated payloads

- 🔬 **VirusTotal Integration**
  - File and domain reputation analysis using VT API

- 📚 **CVE Lookup**
  - Fetches real-time CVE details from NVD

- 🌐 **Nmap Scanner Integration**
  - Runs port scans and service detection on target domains/IPs

- 🧪 **Process Memory Inspection**
  - Scans running processes for injected code or anomalies

---

## 📦 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourname/mvtrack.git
cd mvtrack
pip install -r requirements.txt
python3 mvtrack.py

---

### 🚀 Usage

python3 mvtrack.py --help

- 🔍 File Analysis
python3 mvtrack.py -f <filename> -v

- 🌐 Nmap Scan
python3 mvtrack.py -i <ip> -v

- 🧠 Memory Scan (Scan running processes in system memory.)
python3 mvtrack.py --memory

- 📡 Network Analysis(Monitor and analyze suspicious packets on the network.)
python3 mvtrack.py --network

- 🧾 Output Results to JSON File
python3 mvtrack.py -f <file> -o report.json

- 🔍 CVE Search by Keyword
python3 mvtrack.py -k <keyword>
ex -
python3 mvtrack.py -k "openssl"

- 💉 Force VirusTotal Upload (skip cache)
python3 mvtrack.py -f <file> --force
