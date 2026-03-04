import requests

def search(username):
    print(f"[Username Search] Searching for username: {username}")
    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "Facebook": f"https://facebook.com/{username}"
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }
    for platform, url in platforms.items():
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                print(f"[+] Found on {platform}: {url}")
            elif resp.status_code == 404:
                print(f"[-] Not found on {platform}")
            else:
                print(f"[?] {platform} returned status {resp.status_code}")
        except requests.RequestException as e:
            print(f"[!] Error checking {platform}: {e}")
