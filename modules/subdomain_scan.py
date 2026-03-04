import requests
import colorama
import json

def scan(domain):
    print(f"{colorama.Fore.RED}[*] Initiating Subdomain Scan for: {domain} via CRT.sh...{colorama.Style.RESET_ALL}")
    
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    try:
        response = requests.get(url, timeout=20)
        
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            
            for entry in data:
                name_value = entry['name_value']
                # CRT.sh can return multiple domains in one string separated by newlines
                for sub in name_value.split('\n'):
                    if domain in sub:
                         subdomains.add(sub)
            
            if subdomains:
                print(f"{colorama.Fore.WHITE}[+] Found {len(subdomains)} unique subdomains:{colorama.Style.RESET_ALL}")
                for sub in sorted(subdomains):
                    print(f"{colorama.Fore.RED}  -> {sub}{colorama.Style.RESET_ALL}")
            else:
                print(f"{colorama.Fore.WHITE}[-] No subdomains found in public logs.{colorama.Style.RESET_ALL}")
        else:
             print(f"{colorama.Fore.WHITE}[!] CRT.sh returned status: {response.status_code}{colorama.Style.RESET_ALL}")

    except json.JSONDecodeError:
         print(f"{colorama.Fore.WHITE}[!] Error parsing JSON from CRT.sh (API might be unstable).{colorama.Style.RESET_ALL}")
    except requests.RequestException as e:
        print(f"{colorama.Fore.WHITE}[!] Connection error: {e}{colorama.Style.RESET_ALL}")
