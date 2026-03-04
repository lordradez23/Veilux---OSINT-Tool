import argparse
import os
import colorama
colorama.init()
from modules import phone_lookup, username_search, metadata_extractor, domain_ip_lookup, geolocation, shodan_search, ip_by_map, live_tracking, email_breach, dns_enum, port_scanner, mac_lookup, url_unshortener, google_dorks, visuals, subdomain_scan, tech_detect, google_history

def banner():
    RED = '\033[91m'
    GREEN = '\033[92m'
    CYAN = '\033[97m' # Changed to WHITE/BRIGHT GREY for "Dangerous" contrast
    YELLOW = '\033[91m' # Changed to RED for highlighted items
    RESET = '\033[0m'
    BOLD = '\033[1m'
    # ASCII Art
    print(rf"""
{BOLD}{RED}██╗   ██╗███████╗██╗██╗     ██╗   ██╗██╗  ██╗{RESET}{CYAN}     /\___/\
{BOLD}{RED}██║   ██║██╔════╝██║██║     ██║   ██║╚██╗██╔╝{RESET}{CYAN}    (@ @)
{BOLD}{RED}██║   ██║█████╗  ██║██║     ██║   ██║ ╚███╔╝ {RESET}{CYAN}     )===( 
{BOLD}{RED}╚██╗ ██╔╝██╔══╝  ██║██║     ██║   ██║ ██╔██╗ {RESET}{CYAN}    /|   |\
{BOLD}{RED} ╚████╔╝ ███████╗██║███████╗╚██████╔╝██╔╝ ██╗{RESET}{CYAN}   / | | | \
{BOLD}{RED}  ╚═══╝  ╚══════╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝{RESET}{CYAN}  *  * *  *
{RESET}""")
    print(f"{CYAN}{BOLD}By Lordradeez.exe{RESET}\n")
    print(f"{YELLOW}{BOLD}Weaponized OSINT Exploitation Framework - Unstoppable Digital Warfare{RESET}")
    print(f"{CYAN}{'-'*60}{RESET}")
    visuals.random_quote()

def main():
    visuals.matrix_rain(duration=3)
    visuals.aggressive_boot()
    banner()
    while True:
        RED = '\033[91m'
        GREEN = '\033[92m'
        CYAN = '\033[97m' # White
        YELLOW = '\033[91m' # Red
        RESET = '\033[0m'
        BOLD = '\033[1m'
        print(f"""
{YELLOW}{BOLD}[1]{RESET} {CYAN}Phone Lookup{RESET}

{YELLOW}{BOLD}[2]{RESET} {CYAN}Username Search{RESET}

{YELLOW}{BOLD}[3]{RESET} {CYAN}Metadata Extraction{RESET}

{YELLOW}{BOLD}[4]{RESET} {CYAN}Domain/IP Lookup{RESET}

{YELLOW}{BOLD}[5]{RESET} {CYAN}Geolocation Trace{RESET}

{YELLOW}{BOLD}[6]{RESET} {CYAN}Shodan Search{RESET}

{YELLOW}{BOLD}[7]{RESET} {CYAN}Update Tool{RESET}

{YELLOW}{BOLD}[8]{RESET} {CYAN}IP by Map{RESET}

{YELLOW}{BOLD}[9]{RESET} {CYAN}Live Tracking{RESET}

{YELLOW}{BOLD}[10]{RESET} {CYAN}Email Breach Check{RESET}

{YELLOW}{BOLD}[11]{RESET} {CYAN}DNS Enumeration{RESET}

{YELLOW}{BOLD}[12]{RESET} {CYAN}Port Scanner{RESET}

{YELLOW}{BOLD}[13]{RESET} {CYAN}MAC Address Lookup{RESET}

{YELLOW}{BOLD}[14]{RESET} {CYAN}URL Unshortener{RESET}

{YELLOW}{BOLD}[15]{RESET} {CYAN}Google Dorks Helper{RESET}

{YELLOW}{BOLD}[16]{RESET} {CYAN}Subdomain Scanner (CRT.sh){RESET}

{YELLOW}{BOLD}[17]{RESET} {CYAN}CMS & Tech Detector{RESET}

{YELLOW}{BOLD}[18]{RESET} {CYAN}Google History Scanner (OSINT){RESET}

{YELLOW}{BOLD}[99]{RESET} {RED}About{RESET}

{YELLOW}{BOLD}[0]{RESET} {RED}Exit{RESET}
""")
        try:
            choice = input(f"{GREEN}{BOLD}Select an option: {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{RED}Exiting. Goodbye!{RESET}")
            break
        if choice == "1":
            number = input(f"{CYAN}Enter phone number: {RESET}").strip()
            phone_lookup.lookup(number)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "2":
            username = input(f"{CYAN}Enter username: {RESET}").strip()
            username_search.search(username)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "3":
            file_path = input(f"{CYAN}Enter file path: {RESET}").strip()
            metadata_extractor.extract(file_path)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "4":
            target = input(f"{CYAN}Enter domain or IP: {RESET}").strip()
            domain_ip_lookup.lookup(target)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "5":
            target = input(f"{CYAN}Enter IP or domain: {RESET}").strip()
            geolocation.trace(target)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "6":
            target = input(f"{CYAN}Enter IP or domain for Shodan: {RESET}").strip()
            shodan_search.search(target)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "7":
            import subprocess
            print(f"{YELLOW}Updating Veilux...{RESET}")
            try:
                result = subprocess.run(["git", "pull"], capture_output=True, text=True)
                print(result.stdout)
                if result.stderr:
                    print(f"{RED}{result.stderr}{RESET}")
                print(f"{GREEN}Update complete! Restart the tool if necessary.{RESET}")
            except Exception as e:
                print(f"{RED}Update failed: {e}{RESET}")
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "8":
            ip_or_domain = input(f"{CYAN}Enter IP or domain: {RESET}").strip()
            ip_by_map.map_ip(ip_or_domain)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "9":
            ip_or_domain = input(f"{CYAN}Enter IP or domain: {RESET}").strip()
            interval = input(f"{CYAN}Enter update interval in seconds (default 10): {RESET}").strip()
            try:
                interval = int(interval) if interval else 10
            except ValueError:
                interval = 10
            live_tracking.live_track(ip_or_domain, interval)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "10":
            email = input(f"{CYAN}Enter email address: {RESET}").strip()
            email_breach.check(email)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "11":
            domain = input(f"{CYAN}Enter domain: {RESET}").strip()
            dns_enum.enum(domain)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "12":
            target = input(f"{CYAN}Enter IP or domain: {RESET}").strip()
            port_scanner.scanner(target)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "13":
            mac_addr = input(f"{CYAN}Enter MAC Address (e.g. 00:1A:2B...): {RESET}").strip()
            mac_lookup.lookup(mac_addr)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "14":
            url = input(f"{CYAN}Enter short URL: {RESET}").strip()
            url_unshortener.unshorten(url)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "15":
            domain = input(f"{CYAN}Enter domain for dorks: {RESET}").strip()
            google_dorks.generate(domain)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "16":
            domain = input(f"{CYAN}Enter domain to scan (e.g. google.com): {RESET}").strip()
            subdomain_scan.scan(domain)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "17":
            target = input(f"{CYAN}Enter URL to analyze: {RESET}").strip()
            tech_detect.analyze(target)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "18":
            email = input(f"{CYAN}Enter target Gmail/Email: {RESET}").strip()
            google_history.scan(email)
            input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
        elif choice == "99":
            print(f"\n{BOLD}{CYAN}Veilux - OSINT Tool\nBy Lordradeez.exe\nStealthy, Fast, Reliable OSINT Recon{RESET}\n")
        elif choice == "0":
            print(f"{RED}Exiting. Goodbye!{RESET}")
            break
        else:
            print(f"{RED}Invalid option. Please try again.{RESET}")

if __name__ == "__main__":
    main()
