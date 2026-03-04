import requests
import colorama

def analyze(target):
    if not target.startswith("http"):
        target = "http://" + target
        
    print(f"{colorama.Fore.RED}[*] Analyzing Technology Stack for: {target}...{colorama.Style.RESET_ALL}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    try:
        response = requests.get(target, headers=headers, timeout=10)
        
        # Header Analysis
        print(f"\n{colorama.Fore.WHITE}[Server Headers]{colorama.Style.RESET_ALL}")
        interesting_headers = ['Server', 'X-Powered-By', 'X-Generator', 'Via', 'X-AspNet-Version']
        for header, value in response.headers.items():
            if header in interesting_headers:
                print(f"{colorama.Fore.RED}  {header}: {value}{colorama.Style.RESET_ALL}")
        
        # Content Analysis (Simple CMS Detection)
        print(f"\n{colorama.Fore.WHITE}[CMS / Tech Detection]{colorama.Style.RESET_ALL}")
        content = response.text.lower()
        
        techs = {
            "WordPress": ["wp-content", "wp-includes"],
            "Joomla": ["joomla"],
            "Drupal": ["drupal"],
            "Shopify": ["myshopify"],
            "Wix": ["wix.com"],
            "React": ["react-dom", "react"],
            "Angular": ["ng-version"],
            "Vue.js": ["vue.js"],
            "Bootstrap": ["bootstrap.css", "bootstrap.js"],
            "jQuery": ["jquery"],
        }
        
        found_tech = []
        for tech, signatures in techs.items():
            for sig in signatures:
                if sig in content:
                    found_tech.append(tech)
                    break
        
        if found_tech:
            for t in found_tech:
                 print(f"{colorama.Fore.RED}  [+] Detected: {t}{colorama.Style.RESET_ALL}")
        else:
             print(f"{colorama.Fore.WHITE}  [-] No common CMS signatures detected.{colorama.Style.RESET_ALL}")

    except requests.RequestException as e:
        print(f"{colorama.Fore.WHITE}[!] Analysis failed: {e}{colorama.Style.RESET_ALL}")
