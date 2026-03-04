import colorama
import urllib.parse

def scan(email):
    """
    Scans for sites and public activity associated with a Gmail address using OSINT techniques.
    """
    colorama.init()
    CYAN = colorama.Fore.CYAN
    YELLOW = colorama.Fore.YELLOW
    GREEN = colorama.Fore.GREEN
    RESET = colorama.Style.RESET_ALL
    BOLD = colorama.Style.BRIGHT

    print(f"\n{CYAN}{BOLD}[*] Initiating Digital Footprint Scan for: {email}{RESET}\n")

    # Grouped Google Dorks for specific reconnaissance vectors
    dork_categories = {
        "Social Media & Profiles": [
            f'"{email}" site:linkedin.com',
            f'"{email}" site:facebook.com',
            f'"{email}" site:twitter.com OR site:x.com',
            f'"{email}" site:instagram.com',
            f'"{email}" site:github.com',
            f'"{email}" site:reddit.com',
            f'"{email}" site:stackoverflow.com',
            f'"{email}" site:medium.com'
        ],
        "Forums & Communities": [
            f'"{email}" site:quora.com',
            f'"{email}" site:pastebin.com',
            f'"{email}" site:hackernews.com',
            f'"{email}" site:discord.com',
            f'"{email}" intext:"{email}" forum'
        ],
        "Public Documents & Data Leaks": [
            f'site:*.gov "{email}"',
            f'site:*.edu "{email}"',
            f'filetype:pdf "{email}"',
            f'filetype:xls OR filetype:xlsx "{email}"',
            f'filetype:doc OR filetype:docx "{email}"',
            f'"{email}" "password" OR "login" OR "account"'
        ],
        "Website Registrations & Mentions": [
            f'intext:"{email}" -site:google.com',
            f'inurl:"{email.split("@")[0]}"',
            f'intitle:"{email}"'
        ]
    }

    print(f"{YELLOW}--- GENERATED RECONNAISSANCE QUERIES ---{RESET}")
    
    for category, queries in dork_categories.items():
        print(f"\n{GREEN}[+] {category}{RESET}")
        for query in queries:
            encoded_query = urllib.parse.quote(query)
            link = f"https://www.google.com/search?q={encoded_query}"
            print(f"  > {YELLOW}{query}{RESET}")
            # print(f"    URL: {link}") # Optional: show the direct search link

    print(f"\n{CYAN}{BOLD}[!] ACTION REQUIRED:{RESET}")
    print(f"{CYAN}Copy and paste these queries into your browser to explore the results.{RESET}")
    print(f"{CYAN}Use a VPN or proxy if running multiple intensive searches to avoid CAPTCHAs.{RESET}")

if __name__ == "__main__":
    # Test call
    import sys
    if len(sys.argv) > 1:
        scan(sys.argv[1])
    else:
        print("Usage: python google_history.py <email>")
