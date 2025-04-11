import os
import socket
import hashlib
import requests
import base64
from cryptography.fernet import Fernet
from datetime import datetime

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
    Cybersecurity Multitool | Created by Hacky-7 | v5.0
"""
    print(f"\033[92m{banner}\033[0m")
    print("Welcome to the Cybersecurity Multitool! Use responsibly.\n")


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


def md5_hash_generator():
    text = input("Enter the Text to Hash: ")
    result = hashlib.md5(text.encode()).hexdigest()
    print(f"[+] MD5 Hash: {result}")
    input("\nPress Enter to return to the menu...")


def whois_lookup():
    domain = input("Enter the Domain: ")
    print(f"Performing WHOIS lookup for {domain}...\n")
    try:
        response = requests.get(f"https://whois.domaintools.com/{domain}")
        if response.status_code == 200:
            print(response.text)
        else:
            print(f"[!] Error fetching WHOIS data for {domain}")
    except Exception as e:
        print(f"[!] Error: {e}")
    input("\nPress Enter to return to the menu...")


def base64_encoder_decoder():
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


def aes_encrypt_decrypt():
    action = input("Choose Action (encrypt/decrypt): ").strip().lower()
    key = Fernet.generate_key()
    cipher = Fernet(key)
    if action == "encrypt":
        text = input("Enter the Text to Encrypt: ")
        encrypted = cipher.encrypt(text.encode())
        print(f"[+] Encrypted Text: {encrypted.decode()}")
        print(f"[+] Encryption Key: {key.decode()}")
    elif action == "decrypt":
        encrypted_text = input("Enter the Text to Decrypt: ")
        key = input("Enter the Encryption Key: ").encode()
        try:
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode())
            print(f"[+] Decrypted Text: {decrypted.decode()}")
        except Exception as e:
            print(f"[!] Error decrypting text: {e}")
    input("\nPress Enter to return to the menu...")


# ====== Paginated Menu ======

TOOLS = [
    "Port Scanner", "Subdomain Enumerator", "Ping Sweep", "Traceroute", "DNS Zone Transfer Checker",
    "WHOIS Lookup", "IP Geolocation Finder", "Email Validator", "Metadata Extractor", "Social Media Finder",
    "MD5 Hash Generator", "SHA256 Hash Generator", "Base64 Encoder/Decoder", "Caesar Cipher", "AES Encryption/Decryption",
    "SQL Injection Tester", "XSS Payload Injector", "Directory Brute-Forcer", "Open Redirect Tester", "Command Injection Tester",
    "Reverse Shell Generator", "Keylogger Simulator", "Privilege Escalation Checker", "Network Sniffer", "System Info Enumerator",
    "SSL Certificate Checker", "Website Screenshot Capturer", "Public Breach Checker", "Shodan API Integration", "Google Dorker",
    "Pastebin Scraper", "HMAC Generator", "RSA Key Generator", "XOR Cipher Tool", "PGP Key Generator",
    "Password Strength Checker", "Hash Collision Finder", "File Upload Tester", "Local File Inclusion Tester",
    "Remote File Inclusion Tester", "Shellshock Vulnerability Checker", "Basic Vulnerability Scanner", "Process Hijacking Simulator",
    "Data Exfiltration Simulator", "Malware Scanner", "Network Mapper", "HTTP Header Analyzer", "Reverse DNS Lookup"
]

TOOLS_PER_PAGE = 10


def show_paginated_menu(page):
    os.system('cls' if os.name == 'nt' else 'clear')
    print_hacker_banner()
    start = (page - 1) * TOOLS_PER_PAGE
    end = start + TOOLS_PER_PAGE
    tools = TOOLS[start:end]

    print(f"\033[94mPage {page}/{(len(TOOLS) + TOOLS_PER_PAGE - 1) // TOOLS_PER_PAGE}\033[0m\n")
    for i, tool in enumerate(tools, start=1):
        print(f"{i}. {tool}")
    print("\nN. Next Page")
    print("B. Previous Page")
    print("Q. Quit")
    print("\n")


def main():
    current_page = 1
    while True:
        show_paginated_menu(current_page)
        choice = input("Enter your choice: ").strip().lower()

        if choice == "n":
            if current_page < (len(TOOLS) + TOOLS_PER_PAGE - 1) // TOOLS_PER_PAGE:
                current_page += 1
            else:
                print("\033[91m[!] Already on the last page.\033[0m")
        elif choice == "b":
            if current_page > 1:
                current_page -= 1
            else:
                print("\033[91m[!] Already on the first page.\033[0m")
        elif choice == "q":
            print("\033[91mExiting... Stay Safe! 🛡️\033[0m")
            break
        elif choice.isdigit() and 1 <= int(choice) <= TOOLS_PER_PAGE:
            tool_index = (current_page - 1) * TOOLS_PER_PAGE + int(choice) - 1
            if tool_index < len(TOOLS):
                tool_name = TOOLS[tool_index]
                print(f"\033[92m[+] Selected Tool: {tool_name}\033[0m")
                # Call relevant tool function here (e.g., if tool_name == "Port Scanner": port_scanner())
            else:
                print("\033[91m[!] Invalid Choice.\033[0m")
        else:
            print("\033[91m[!] Invalid Choice.\033[0m")


if __name__ == "__main__":
    main()
