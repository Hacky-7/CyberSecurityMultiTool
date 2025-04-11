import argparse
import socket
import hashlib
import requests
import base64
from cryptography.fernet import Fernet

# ====== Scanning and Reconnaissance ======

def port_scanner(target, ports):
    print(f"Scanning ports on {target}...")
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    print(f"[+] Port {port} is open.")
                else:
                    print(f"[-] Port {port} is closed.")
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")

def banner_grabber(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.1\r\n\r\n")
            banner = s.recv(1024).decode()
            print(f"[+] Banner: {banner}")
    except Exception as e:
        print(f"[!] Error grabbing banner: {e}")

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] {domain} resolved to {ip}")
    except Exception as e:
        print(f"[!] Error resolving domain: {e}")

def subdomain_enumerator(domain):
    subdomains = ['www', 'mail', 'ftp', 'dev']
    print(f"Enumerating subdomains for {domain}...")
    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            print(f"[+] {subdomain} resolved to {ip}")
        except:
            print(f"[-] {subdomain} not found.")

def reverse_dns_lookup(ip):
    try:
        host = socket.gethostbyaddr(ip)
        print(f"[+] Reverse DNS for {ip}: {host[0]}")
    except Exception as e:
        print(f"[!] Error resolving reverse DNS: {e}")

def ssl_certificate_checker(domain):
    try:
        import ssl
        import datetime
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                valid_until = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                print(f"[+] SSL Certificate valid until: {valid_until}")
    except Exception as e:
        print(f"[!] Error checking SSL certificate: {e}")

# ====== Cryptography ======

def md5_hash_generator(text):
    result = hashlib.md5(text.encode()).hexdigest()
    print(f"[+] MD5 Hash: {result}")

def sha256_hash_generator(text):
    result = hashlib.sha256(text.encode()).hexdigest()
    print(f"[+] SHA256 Hash: {result}")

def base64_encoder(text):
    encoded = base64.b64encode(text.encode()).decode()
    print(f"[+] Base64 Encoded: {encoded}")

def base64_decoder(encoded_text):
    decoded = base64.b64decode(encoded_text).decode()
    print(f"[+] Base64 Decoded: {decoded}")

def password_strength_checker(password):
    strength = "Weak"
    if len(password) >= 8 and any(c.isdigit() for c in password) and any(c.isalpha() for c in password):
        strength = "Medium"
    if len(password) >= 12 and any(c.isdigit() for c in password) and any(c.isalpha() for c in password) and any(c in "!@#$%^&*()" for c in password):
        strength = "Strong"
    print(f"[+] Password Strength: {strength}")

def caesar_cipher_encrypt(text, shift):
    encrypted = ''.join(chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else chr((ord(char) - 97 + shift) % 26 + 97) if char.islower() else char for char in text)
    print(f"[+] Encrypted Text: {encrypted}")

def caesar_cipher_decrypt(text, shift):
    decrypted = ''.join(chr((ord(char) - 65 - shift) % 26 + 65) if char.isupper() else chr((ord(char) - 97 - shift) % 26 + 97) if char.islower() else char for char in text)
    print(f"[+] Decrypted Text: {decrypted}")

# ====== OSINT ======

def website_screenshot(url):
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        driver.save_screenshot('screenshot.png')
        driver.quit()
        print("[+] Screenshot saved as screenshot.png")
    except Exception as e:
        print(f"[!] Error capturing screenshot: {e}")

def shodan_search(api_key, query):
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}")
        if response.status_code == 200:
            data = response.json()
            print(f"[+] Shodan Results: {data}")
        else:
            print(f"[!] Shodan Error: {response.text}")
    except Exception as e:
        print(f"[!] Shodan API Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Multitool (Educational Purposes Only)")
    subparsers = parser.add_subparsers(dest="command", help="Available tools")

    # Port Scanner
    port_scanner_parser = subparsers.add_parser("portscan", help="Perform a port scan")
    port_scanner_parser.add_argument("target", help="Target IP or hostname")
    port_scanner_parser.add_argument("ports", nargs="+", type=int, help="List of ports to scan")

    # Subdomain Enumerator
    subdomain_enum_parser = subparsers.add_parser("subdomainenum", help="Enumerate subdomains")
    subdomain_enum_parser.add_argument("domain", help="Target domain")

    # Base64 Encoder/Decoder
    base64_parser = subparsers.add_parser("base64", help="Encode/Decode Base64")
    base64_parser.add_argument("action", choices=["encode", "decode"], help="Action to perform")
    base64_parser.add_argument("text", help="Text to encode/decode")

    # SSL Certificate Checker
    ssl_parser = subparsers.add_parser("sslcheck", help="Check SSL Certificate")
    ssl_parser.add_argument("domain", help="Domain to check")

    # Shodan Search
    shodan_parser = subparsers.add_parser("shodan", help="Search Shodan")
    shodan_parser.add_argument("api_key", help="Your Shodan API Key")
    shodan_parser.add_argument("query", help="Query to search")

    # Parse arguments
    args = parser.parse_args()

    if args.command == "portscan":
        port_scanner(args.target, args.ports)
    elif args.command == "subdomainenum":
        subdomain_enumerator(args.domain)
    elif args.command == "base64":
        if args.action == "encode":
            base64_encoder(args.text)
        else:
            base64_decoder(args.text)
    elif args.command == "sslcheck":
        ssl_certificate_checker(args.domain)
    elif args.command == "shodan":
        shodan_search(args.api_key, args.query)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
