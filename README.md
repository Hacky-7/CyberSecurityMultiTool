# 🔐 Cybersecurity Multitool (Educational Purposes Only)

Welcome to the **Cybersecurity Multitool**! This is your one-stop solution for learning and experimenting with various cybersecurity concepts. It includes tools for **scanning**, **OSINT**, **cryptography**, and **post-exploitation** – all in one Python script! 🚀

> **⚠️ Disclaimer**: This tool is strictly for **educational purposes**. Please ensure you have proper authorization before testing on any system. Unauthorized use of this tool is illegal and unethical.

---

## 🌟 Features

This multitool includes **50+ cybersecurity tools**, divided into the following categories:

### 🔍 Scanning and Reconnaissance
- **Port Scanner**: Scan open ports on a target.
- **Banner Grabber**: Retrieve service banners for open ports.
- **Subdomain Enumerator**: Identify subdomains of a domain.
- **HTTP Header Analyzer**: Analyze HTTP headers of a website.
- **SSL Certificate Checker**: Check SSL certificate validity.

### 🕵️ OSINT (Open Source Intelligence)
- **WHOIS Lookup**: Get WHOIS information for a domain.
- **IP Geolocation**: Find location data for an IP.
- **Reverse DNS Lookup**: Resolve IPs to hostnames.
- **Website Screenshot Capturer**: Take a screenshot of a website.
- **Shodan API Integration**: Search for devices using Shodan.

### 🔐 Cryptography
- **MD5 & SHA256 Hash Generators**.
- **Base64 Encoder/Decoder**.
- **Caesar Cipher Encrypt/Decrypt**.
- **Password Strength Checker**.
- **AES & RSA Encryption/Decryption** (Coming Soon).

### 🛠️ Post-Exploitation
- **Simple Reverse Shell Generator**.
- **Data Exfiltration Simulator** (Educational).
- **Privilege Escalation Checker** (Basic).

---

## 🛠️ Setup Guide

### 1️⃣ Prerequisites
Ensure you have the following installed:
- Python 3.7 or higher 🐍
- `pip` (Python package manager)

### 2️⃣ Clone the Repository
```bash
git clone https://github.com/Hacky-7/cybersecurity-multitool.git
cd cybersecurity-multitool
```

### 3️⃣ Install Dependencies
Install the required libraries using `pip`:
```bash
pip install -r requirements.txt
```

### 4️⃣ Install ChromeDriver (For Website Screenshots)
For the **Website Screenshot Capturer**, download and install **ChromeDriver**:
1. [Download ChromeDriver here](https://chromedriver.chromium.org/downloads).
2. Ensure the version matches your Chrome browser.
3. Add the ChromeDriver to your system `PATH`.

---

## 🚀 Usage Guide

Run the multitool script with:
```bash
python cybersecurity_multitool.py <command> [options]
```

### Example Commands

#### 🔍 Port Scanning
Scan open ports on a target:
```bash
python cybersecurity_multitool.py portscan 127.0.0.1 80 443
```

#### 🕵️ Subdomain Enumeration
Find subdomains of a domain:
```bash
python cybersecurity_multitool.py subdomainenum example.com
```

#### 🔐 Generate MD5 Hash
Generate an MD5 hash for a string:
```bash
python cybersecurity_multitool.py md5hash "example"
```

#### 🔁 Base64 Encoding/Decoding
- Encode a string to Base64:
  ```bash
  python cybersecurity_multitool.py base64 encode "hello world"
  ```
- Decode a Base64 string:
  ```bash
  python cybersecurity_multitool.py base64 decode "aGVsbG8gd29ybGQ="
  ```

#### 🌐 Website Screenshot
Capture a screenshot of a website:
```bash
python cybersecurity_multitool.py screenshot https://example.com
```

---

## 📂 File Structure

```
cybersecurity-multitool/
├── cybersecurity_multitool.py   # Main script
├── requirements.txt             # Dependencies
├── README.md                    # This file
└── tools/                       # Individual tools (modular structure)
    ├── port_scanner.py
    ├── subdomain_enum.py
    ├── cryptography_tools.py
    ├── ...
```

---

## 🛡️ Legal & Ethical Notice

1. Use this tool **only on systems you own** or have **explicit permission** to test.
2. Unauthorized usage is a violation of **cybersecurity laws** and could lead to serious legal consequences.
3. The developer is **not responsible** for misuse of this tool.

---

## ❤️ Contribute

Want to add more tools or improve the existing ones? Feel free to fork this repository and submit a pull request! 🤝

---

## 🌐 License

This project is licensed under the [MIT License](LICENSE). You are free to use, modify, and distribute this tool as long as proper credit is given. 👍

---

## 🧑‍💻 Author

**Hacky-7**  
GitHub: [Hacky-7](https://github.com/Hacky-7)

---

Happy Learning & Ethical Hacking! 🎉 🛡️
