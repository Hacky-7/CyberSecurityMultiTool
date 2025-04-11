import os
import socket
import hashlib
import base64
import requests
import time

# ====== Styling ======
def print_hacker_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = """
 ██████╗██╗   ██╗██████╗ ███████╗███████╗██╗   ██╗ ██████╗██╗   ██╗
██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝██║   ██║██╔════╝╚██╗ ██╔╝
██║     ██║   ██║██████╔╝█████╗  █████╗  ██║   ██║██║  ███╗╚████╔╝ 
██║     ██║   ██║██╔═══╝ ██╔══╝  ██╔══╝  ██║   ██║██║   ██║ ╚██╔╝  
╚██████╗╚██████╔╝██║     ███████╗███████╗╚██████╔╝╚██████╔╝  ██║   
 ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝ ╚═════╝  ╚═════╝   ╚═╝   
    Cybersecurity Multitool | Created by Hacky-7 | v2.0
"""
    print(f"\033[92m{banner}\033[0m")
    print("Welcome to the Cybersecurity Multitool! Use responsibly.\n")

def print_menu():
    print("\033[94mSelect a Tool:\033[0m")
    print("1. 🔍 Port Scanner")
    print("2. 🌐 Subdomain Enumerator")
    print("3. 🔐 Base64 Encoder/Decoder")
    print("4. 🛡️  SSL Certificate Checker")
    print("5. 🕵️  Shodan Search")
    print("6. ❌ Exit")
    print("\n")

# ====== Tools ======

def port_scanner():
    target = input("Enter the Target IP/Hostname: ")
    ports = input("Enter Ports to Scan (comma-separated): ")
    ports = [int(p.strip()) for p in ports.split(",")]
    print(f"Scanning ports on {target}...\n")
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    print(f"[+] Port {port} is OPEN.")
                else:
                    print(f"[-] Port {port} is CLOSED.")
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")
    input("\nPress Enter to return to the menu...")

def subdomain_enumerator():
    domain = input("Enter the Target Domain: ")
    subdomains = ['www', 'mail', 'ftp', 'dev']
    print(f"Enumerating subdomains for {domain}...\n")
    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            print(f"[+] {subdomain} resolved to {ip}")
        except:
            print(f"[-] {subdomain} not found.")
    input("\nPress Enter to return to the menu...")

def base64_tool():
    action = input("Choose Action (encode/decode): ").strip().lower()
    text = input("Enter the Text: ")
    if action == "encode":
        encoded = base64.b64encode(text.encode()).decode()
        print(f"[+] Encoded Text: {encoded}")
    elif action == "decode":
        try:
            decoded = base64.b64decode(text).decode()
            print(f"[+] Decoded Text: {decoded}")
        except Exception as e:
            print(f"[!] Error decoding text: {e}")
    else:
        print("[!] Invalid Action. Choose 'encode' or 'decode'.")
    input("\nPress Enter to return to the menu...")

def ssl_certificate_checker():
    domain = input("Enter the Domain: ")
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
    input("\nPress Enter to return to the menu...")

def shodan_search():
    api_key = input("Enter Your Shodan API Key: ")
    query = input("Enter the Search Query: ")
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}")
        if response.status_code == 200:
            data = response.json()
            print(f"[+] Shodan Results: {data}")
        else:
            print(f"[!] Shodan Error: {response.text}")
    except Exception as e:
        print(f"[!] Shodan API Error: {e}")
    input("\nPress Enter to return to the menu...")

# ====== Main Loop ======

def main():
    while True:
        print_hacker_banner()
        print_menu()
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            port_scanner()
        elif choice == "2":
            subdomain_enumerator()
        elif choice == "3":
            base64_tool()
        elif choice == "4":
            ssl_certificate_checker()
        elif choice == "5":
            shodan_search()
        elif choice == "6":
            print("\033[91mExiting... Stay Safe! 🛡️\033[0m")
            time.sleep(1)
            break
        else:
            print("\033[91m[!] Invalid Choice. Try Again.\033[0m")
            time.sleep(1)

if __name__ == "__main__":
    main()
