# 🔐 URL Scanner CLI

Cyber-style URL scanning tool built with Node.js.  
This tool analyzes URLs using multiple sources:

- 🌐 URL structure analysis  
- 🔐 SSL validation  
- 🧠 VirusTotal integration  
- 📡 AbuseIPDB (IP reputation)

---

## 🚀 Features

- Scan single URL
- Multi-target scan (`--multi`, `-m`)
- Save output to file (`--output`, `-o`)
- CLI interface

---

## ⚙️ Setup & Usage Guide

Follow these steps to run the URL Scanner CLI on your machine.

---

### 1. Clone the Repository

```bash
git clone https://github.com/abdulcoder207/url-scanner.git
cd url-scanner
```
### 2. Install Dependencies
```bash
npm install
```
### 3. Setup Environment Variables
```bash
This project requires API keys from:

VirusTotal
AbuseIPDB

Create a .env file:

cp .env.example .env

Then open .env and fill in your API keys:

VT_API_KEY=your_virustotal_api_key
ABUSE_API_KEY=your_abuseipdb_api_key
```

### 4. Run as CLI Tool

```bash
Register the CLI globally:

npm link

Now you can use the command:

urlscan scan https://example.com
```

### 5. Scan Multiple Targets
```bash
Create a file (e.g. targets.txt):

https://google.com
https://github.com
https://example.com

Run:
urlscan scan targets.txt --multi
```

### 6. Save Output to File
```bash
urlscan scan https://example.com --output result.json
```

### 7. Notes
```bash
Free API keys have rate limits
Some scans may take a few seconds
Results depend on external services (VirusTotal, AbuseIPDB)
```
