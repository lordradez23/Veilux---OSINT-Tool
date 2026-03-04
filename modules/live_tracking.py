import requests
import time

def live_track(ip_or_domain, interval=10):
    """
    Continuously fetch and print geolocation for an IP/domain every interval seconds.
    """
    print(f"[Live Tracking] Tracking: {ip_or_domain} (updates every {interval} seconds, Ctrl+C to stop)")
    try:
        while True:
            try:
                response = requests.get(f'https://ipinfo.io/{ip_or_domain}/json', timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    loc = data.get('loc')
                    if loc:
                        lat, lon = loc.split(',')
                        print(f"\nLatitude: {lat}\nLongitude: {lon}")
                        print(f"Google Maps: https://www.google.com/maps?q={lat},{lon}")
                        print(f"OpenStreetMap: https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}")
                    else:
                        print(f"{colorama.Fore.RED}[!] Could not determine location.{colorama.Style.RESET_ALL}")
                else:
                     print(f"{colorama.Fore.WHITE}[!] API Error: {response.status_code}{colorama.Style.RESET_ALL}")
            except requests.RequestException as e:
                print(f"{colorama.Fore.RED}[!] Network Error: {e}{colorama.Style.RESET_ALL}")
            except Exception as e:
                print(f"{colorama.Fore.RED}[!] Unexpected Error: {e}{colorama.Style.RESET_ALL}")
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nLive tracking stopped.")
