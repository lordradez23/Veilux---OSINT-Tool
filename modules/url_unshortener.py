import requests
import colorama

def unshorten(url):
    if not url.startswith("http"):
        url = "http://" + url
        
    print(f"{colorama.Fore.CYAN}Unshortening {url}...{colorama.Style.RESET_ALL}")
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        final_url = response.url
        
        if final_url != url:
            print(f"{colorama.Fore.GREEN}[+] Final Destination: {final_url}{colorama.Style.RESET_ALL}")
            
            # Show redirect chain if interesting
            if len(response.history) > 0:
                print(f"\n{colorama.Fore.YELLOW}Redirect Chain:{colorama.Style.RESET_ALL}")
                for resp in response.history:
                     print(f" -> {resp.url} ({resp.status_code})")
                print(f" -> {final_url} (Final)")
        else:
             print(f"{colorama.Fore.YELLOW}[*] URL did not redirect (or is already the final URL).{colorama.Style.RESET_ALL}")

    except Exception as e:
        print(f"{colorama.Fore.RED}Error unshortening URL: {e}{colorama.Style.RESET_ALL}")
